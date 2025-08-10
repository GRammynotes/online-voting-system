# paste whole app.py content (long). It's the same as the one provided in the ZIP earlier.
# For convenience, copy the following block exactly into backend/app.py
import os
import sqlite3
import csv
import io
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, send_file, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "voting.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4MB

# token serializer for email confirmation and password reset
ts = URLSafeTimedSerializer(app.secret_key)

# --- Database helpers ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def run_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

# --- Initialize DB schema ---
def init_db():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        id_number TEXT,
        email_verified INTEGER DEFAULT 0
    );''')
    c.execute('''CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT
    );''')
    c.execute('''CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        position_id INTEGER NOT NULL,
        photo TEXT,
        bio TEXT,
        approved INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(position_id) REFERENCES positions(id)
    );''')
    c.execute('''CREATE TABLE IF NOT EXISTS elections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        position_id INTEGER NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        visible INTEGER DEFAULT 1,
        FOREIGN KEY(position_id) REFERENCES positions(id)
    );''')
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id INTEGER NOT NULL,
        candidate_id INTEGER NOT NULL,
        election_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (voter_id) REFERENCES users(id),
        FOREIGN KEY (candidate_id) REFERENCES candidates(id),
        FOREIGN KEY (election_id) REFERENCES elections(id)
    );''')
    db.commit()
    # create default admin if none
    cur = c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        pw = generate_password_hash('admin123')
        c.execute("INSERT INTO users (name,email,username,password,role,email_verified) VALUES (?,?,?,?,?,?)",
                  ("Administrator","admin@example.com","admin",pw,"admin",1))
        db.commit()
        print("Default admin created -> username: admin, password: admin123")
    db.close()

if not os.path.exists(DB_PATH):
    init_db()

# --- Utilities ---
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                return abort(403)
            return fn(*args, **kwargs)
        return decorated
    return wrapper

def current_election_for_position(position_id):
    now = datetime.utcnow()
    row = query_db("SELECT * FROM elections WHERE position_id=? ORDER BY id DESC", (position_id,))
    for r in row:
        st = datetime.fromisoformat(r["start_time"])
        et = datetime.fromisoformat(r["end_time"])
        if st <= now <= et:
            return r
    return None

def make_token(email, salt):
    return ts.dumps(email, salt=salt)
def verify_token(token, salt, max_age=3600):
    try:
        email = ts.loads(token, salt=salt, max_age=max_age)
        return email
    except Exception:
        return None

# --- Simple email sender (SendGrid if configured) ---
def send_email(to_email, subject, html):
    # Try SendGrid if API key provided via env
    sg_api = os.environ.get("SENDGRID_API_KEY")
    if sg_api:
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail
            message = Mail(from_email=os.environ.get("FROM_EMAIL","noreply@example.com"),
                           to_emails=to_email, subject=subject, html_content=html)
            sg = SendGridAPIClient(sg_api)
            sg.send(message)
            return True
        except Exception as e:
            app.logger.error("SendGrid error: %s", e)
            return False
    # Fallback: print to console (development)
    print("=== Email (dev) ===")
    print("To:", to_email)
    print("Subject:", subject)
    print(html)
    return True

# ---------- Routes ----------
@app.route('/ping')
def ping():
    return "pong"

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        username = request.form.get('username').strip()
        password = request.form.get('password')
        role = request.form.get('role')
        id_number = request.form.get('id_number') or None
        if role not in ('voter','candidate','admin'):
            flash('Invalid role', 'danger')
            return redirect(url_for('signup'))
        hashed = generate_password_hash(password)
        try:
            run_db("INSERT INTO users (name,email,username,password,role,id_number,email_verified) VALUES (?,?,?,?,?,?,?)",
                   (name,email,username,hashed,role,id_number,0))
            # send verification email
            token = make_token(email, 'email-confirm')
            verify_url = url_for('confirm_email', token=token, _external=True)
            send_email(email, "Verify your email",
                       f"Hello {name},<br>Click to verify: <a href='{verify_url}'>{verify_url}</a>")
            flash('Account created. Check your email to verify.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    email = verify_token(token, 'email-confirm', max_age=60*60*24)
    if not email:
        flash('Verification link invalid or expired', 'danger')
        return redirect(url_for('login'))
    user = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
    if user:
        run_db("UPDATE users SET email_verified=1 WHERE id=?", (user['id'],))
        flash('Email verified. You can now login.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        if user and check_password_hash(user['password'], password):
            if user['email_verified'] == 0:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Welcome, ' + user['name'], 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    # show available positions and current elections
    positions = query_db("SELECT * FROM positions")
    pos_list = []
    for p in positions:
        # check for an active election for this position
        ev = current_election_for_position(p['id'])
        pos_list.append({'id':p['id'],'title':p['title'],'description':p['description'],'active': bool(ev)})
    return render_template('index.html', positions=pos_list)

# --- Candidate application ---
@app.route('/candidate/apply', methods=['GET','POST'])
@login_required(role='candidate')
def candidate_apply():
    uid = session['user_id']
    if request.method == 'POST':
        name = request.form.get('name').strip()
        position_id = int(request.form.get('position_id'))
        bio = request.form.get('bio','').strip()
        photo = None
        if 'photo' in request.files:
            f = request.files['photo']
            if f and allowed_file(f.filename):
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{f.filename}")
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo = f'uploads/{filename}'
        run_db("INSERT INTO candidates (user_id,name,position_id,photo,bio,approved) VALUES (?,?,?,?,?,0)", (uid,name,position_id,photo,bio))
        flash('Candidate application submitted. Await admin approval.', 'success')
        return redirect(url_for('index'))
    positions = query_db('SELECT * FROM positions')
    return render_template('candidate_apply.html', positions=positions)

# --- Admin dashboard ---
@app.route('/admin')
@login_required(role='admin')
def admin_panel():
    candidates = query_db('SELECT c.*, p.title as position_title, u.username as applicant FROM candidates c LEFT JOIN positions p ON c.position_id=p.id LEFT JOIN users u ON c.user_id=u.id ORDER BY c.approved ASC, c.id DESC')
    voters = query_db("SELECT * FROM users WHERE role='voter'")
    positions = query_db('SELECT * FROM positions')
    elections = query_db('SELECT e.*, p.title as position_title FROM elections e LEFT JOIN positions p ON e.position_id=p.id ORDER BY e.id DESC')
    return render_template('admin.html', candidates=candidates, voters=voters, positions=positions, elections=elections)

@app.route('/admin/approve_candidate/<int:candidate_id>', methods=['POST'])
@login_required(role='admin')
def approve_candidate(candidate_id):
    action = request.form.get('action')
    if action == 'approve':
        run_db('UPDATE candidates SET approved=1 WHERE id=?', (candidate_id,))
        flash('Candidate approved', 'success')
    else:
        run_db('DELETE FROM candidates WHERE id=?', (candidate_id,))
        flash('Candidate rejected and removed', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/add_position', methods=['POST'])
@login_required(role='admin')
def add_position():
    title = request.form.get('title').strip()
    desc = request.form.get('description','').strip()
    run_db('INSERT INTO positions (title,description) VALUES (?,?)', (title,desc))
    flash('Position added', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/schedule_election', methods=['POST'])
@login_required(role='admin')
def schedule_election():
    position_id = int(request.form.get('position_id'))
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')
    try:
        st = datetime.fromisoformat(start_time)
        et = datetime.fromisoformat(end_time)
        if et <= st:
            flash('End time must be after start time', 'danger')
            return redirect(url_for('admin_panel'))
        run_db('INSERT INTO elections (position_id,start_time,end_time,visible) VALUES (?,?,?,1)', (position_id, st.isoformat(), et.isoformat()))
        flash('Election scheduled', 'success')
    except Exception as e:
        flash('Invalid datetime format', 'danger')
    return redirect(url_for('admin_panel'))

# Admin: edit/delete users
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('admin_panel'))
    run_db('DELETE FROM users WHERE id=?', (user_id,))
    flash('User deleted', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/candidate/edit/<int:candidate_id>', methods=['GET','POST'])
@login_required(role='admin')
def admin_edit_candidate(candidate_id):
    cand = query_db('SELECT * FROM candidates WHERE id=?', (candidate_id,), one=True)
    if not cand:
        abort(404)
    if request.method == 'POST':
        name = request.form.get('name').strip()
        bio = request.form.get('bio','').strip()
        run_db('UPDATE candidates SET name=?, bio=? WHERE id=?', (name,bio,candidate_id))
        flash('Candidate updated', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin_edit_candidate.html', cand=cand)

# --- Voter panel ---
@app.route('/voter')
@login_required(role='voter')
def voter_panel():
    # show positions and, for each position, whether user can vote (active election and not voted)
    uid = session['user_id']
    positions = query_db('SELECT * FROM positions')
    view = []
    for p in positions:
        ev = current_election_for_position(p['id'])
        voted = False
        if ev:
            v = query_db('SELECT * FROM votes WHERE voter_id=? AND election_id=?', (uid, ev['id']), one=True)
            voted = bool(v)
        view.append({'position':p, 'election':ev, 'voted':voted})
    return render_template('voter.html', view=view)

@app.route('/vote/<int:position_id>', methods=['GET','POST'])
@login_required(role='voter')
def vote(position_id):
    uid = session['user_id']
    ev = current_election_for_position(position_id)
    if not ev:
        flash('No active election for that position', 'danger')
        return redirect(url_for('voter_panel'))
    # check if already voted
    existing = query_db('SELECT * FROM votes WHERE voter_id=? AND election_id=?', (uid, ev['id']), one=True)
    if existing:
        flash('You have already voted in this election', 'warning')
        return redirect(url_for('voter_panel'))
    candidates = query_db('SELECT * FROM candidates WHERE position_id=? AND approved=1', (position_id,))
    if request.method == 'POST':
        candidate_id = int(request.form.get('candidate_id'))
        run_db('INSERT INTO votes (voter_id,candidate_id,election_id,timestamp) VALUES (?,?,?,?)',
               (uid, candidate_id, ev['id'], datetime.utcnow().isoformat()))
        flash('Vote recorded', 'success')
        return redirect(url_for('voter_panel'))
    return render_template('vote.html', candidates=candidates, position_id=position_id, election=ev)

# --- Results ---
@app.route('/results/<int:position_id>')
def results(position_id):
    # show aggregated results for a position and its current or latest election
    election_id = request.args.get('election_id', type=int)
    if not election_id:
        # pick latest election for position
        row = query_db('SELECT * FROM elections WHERE position_id=? ORDER BY id DESC', (position_id,), one=True)
        if not row:
            flash('No election found for this position', 'info')
            return redirect(url_for('index'))
        election_id = row['id']
    election = query_db('SELECT * FROM elections WHERE id=?', (election_id,), one=True)
    results = query_db('SELECT c.id, c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON c.id=v.candidate_id AND v.election_id=? WHERE c.position_id=? GROUP BY c.id', (election_id, election['position_id']))
    return render_template('results.html', results=results, election=election)

@app.route('/admin/download_results/<int:election_id>')
@login_required(role='admin')
def download_results(election_id):
    rows = query_db('SELECT c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON c.id=v.candidate_id AND v.election_id=? WHERE c.position_id=(SELECT position_id FROM elections WHERE id=?) GROUP BY c.id', (election_id,election_id))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Candidate','Votes'])
    for r in rows:
        writer.writerow([r['name'], r['votes']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name=f'results_{election_id}.csv')

# --- Password reset ---
@app.route('/reset_request', methods=['GET','POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        user = query_db('SELECT * FROM users WHERE email=?', (email,), one=True)
        # show generic message
        if user:
            token = make_token(email, 'password-reset')
            reset_url = url_for('reset_with_token', token=token, _external=True)
            send_email(email, 'Password reset', f'Click to reset: {reset_url}')
        flash('If an account with that email exists, you will receive reset instructions.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_with_token(token):
    email = verify_token(token, 'password-reset', max_age=3600)
    if not email:
        flash('Reset link invalid or expired', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        pwd = request.form.get('password')
        hashed = generate_password_hash(pwd)
        run_db('UPDATE users SET password=? WHERE email=?', (hashed,email))
        flash('Password updated. You may login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_with_token.html', token=token)

# --- Search & pagination example for admin candidates list ---
@app.route('/admin/candidates')
@login_required(role='admin')
def admin_candidates_list():
    page = request.args.get('page',1,type=int)
    per_page = 8
    q = request.args.get('q','').strip()
    params = []
    where = ''
    if q:
        where = 'WHERE name LIKE ? OR bio LIKE ?'
        params.extend([f'%{q}%', f'%{q}%'])
    total_row = query_db(f'SELECT COUNT(*) as cnt FROM candidates {where}', params, one=True)
    total = total_row['cnt'] if total_row else 0
    offset = (page-1)*per_page
    params.extend([per_page, offset])
    rows = query_db(f'SELECT * FROM candidates {where} ORDER BY approved ASC, id DESC LIMIT ? OFFSET ?', params)
    total_pages = (total + per_page - 1)//per_page
    return render_template('admin_candidates.html', candidates=rows, page=page, total_pages=total_pages, q=q)

if __name__ == '__main__':
    app.run(debug=True)
