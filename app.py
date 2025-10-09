
from flask import Flask, render_template, request, redirect, url_for, session, flash, render_template_string
from flask_session import Session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
import random
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Replace with an environment variable in production

# --- Configure persistent sessions ---
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "sessions")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
Session(app)

DB_NAME = "users.db"

# --- Database Setup ---
def init_udb():
    if not os.path.exists(DB_NAME):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                );
            """)
        print("Database initialized.")

init_udb()

QUOTA_DB = "quotas.db"

def init_qdb():
    with sqlite3.connect(QUOTA_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quota_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                filesystem TEXT NOT NULL,
                ticket_number TEXT NOT NULL,
                soft_quota TEXT NOT NULL,
                hard_quota TEXT NOT NULL,
                status TEXT DEFAULT 'permanent',
                expiration_date TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Database initialized!")

init_qdb()

# --- Helper functions ---

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=None)  # Enables autocommit-like behavior
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")  # Wait up to 5 seconds for lock
    return conn

def with_retry(max_attempts=5, base_delay=0.1, max_delay=1.0):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            attempts = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e).lower():
                        attempts += 1
                        if attempts >= max_attempts:
                            raise  # Re-raise after max attempts
                        delay = min(max_delay, base_delay * (2 ** (attempts - 1)))
                        jitter = random.uniform(0, delay)
                        time.sleep(jitter)
                    else:
                        raise  # Not a locking error
        return wrapper
    return decorator

def get_user(username):
    with get_db_connection(DB_NAME) as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username=?", (username,))
        return cursor.fetchone()

@with_retry()
def add_user(username, password_hash):
    with get_db_connection(DB_NAME) as conn:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()

def search_quota_requests(name_query, exact=False):
    with get_db_connection(QUOTA_DB) as conn:
        if exact:
            cursor = conn.execute("""
                SELECT id, name, filesystem, ticket_number, soft_quota, hard_quota, status, expiration_date, created_at
                FROM quota_requests
                WHERE name = ?
                ORDER BY created_at DESC
            """, (name_query,))
        else:
            cursor = conn.execute("""
                SELECT id, name, filesystem, ticket_number, soft_quota, hard_quota, status, expiration_date, created_at
                FROM quota_requests
                WHERE name LIKE ?
                ORDER BY created_at DESC
            """, (f"%{name_query}%",))
        return cursor.fetchall()
    
@with_retry()
def insert_quota_request(data):
    with get_db_connection(QUOTA_DB) as conn:
        conn.execute("""
            INSERT INTO quota_requests (name, filesystem, ticket_number, soft_quota, hard_quota, status, expiration_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, data)


# --- Routes ---
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Please fill out all fields.")
            return redirect(url_for('signup'))

        if get_user(username):
            flash("Username already exists.")
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        add_user(username, password_hash)
        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = get_user(username)
        if user and check_password_hash(user[2], password):
            session['user'] = username
            flash("Login successful!")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("You have been logged out.")
    return redirect(url_for('welcome'))

@app.route('/home')
def index():
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/search', methods=['POST'])
def search():
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    name_query = request.form.get('search_name', '').strip()
    if not name_query:
        flash("Please enter a name to search.")
        return redirect(url_for('index'))

    results = search_quota_requests(name_query)
    return render_template('dashboard.html', username=session['user'], results=results, searched_name=name_query)

@app.route('/add_quota', methods=['POST'])
def add_quota():
    name = request.form['name']
    filesystem = request.form['filesystem']
    ticket_number = request.form['ticket_number']
    soft_quota = request.form['soft_quota']
    hard_quota = request.form['hard_quota']
    status = request.form['status']
    expiration_date = None if status == 'permanent' else request.form.get('expiration_date')

    if status == 'temporary' and not expiration_date:
        flash("Expiration date is required for temporary quotas.", "error")
        return redirect(url_for('index'))

    if status == 'permanent':
        expiration_date = None

    data = (name, filesystem, ticket_number, soft_quota, hard_quota, status, expiration_date)
    insert_quota_request(data)

    results = search_quota_requests(name)

    flash("Quota request added successfully!", "success")
    return render_template('dashboard.html', username=session['user'], results=results, searched_name=name)

@app.route('/toggle_expiration')
def toggle_expiration():
    status = request.args.get('status')
    if status == 'temporary':
        return render_template('partials/expiration_input.html')  
    else:
        return ''
    
@app.route('/quota_list/<name>')
def quota_list(name):
    results = search_quota_requests(name, exact=True)
    return render_template('partials/quota_table.html', results=results, searched_name=name)
    
@app.route('/delete_quota/<int:quota_id>', methods=['POST'])
def delete_quota(quota_id):
    if 'user' not in session:
        return "Unauthorized", 403

    # Get name for filtering after deletion
    with get_db_connection(QUOTA_DB) as conn:
        row = conn.execute("SELECT name FROM quota_requests WHERE id = ?", (quota_id,)).fetchone()
        if not row:
            return "Quota not found", 404
        name = row[0]
        conn.execute("DELETE FROM quota_requests WHERE id = ?", (quota_id,))

    # Search remaining entries for that name
    results = search_quota_requests(name, exact=True)

    # Return partial HTML for HTMX
    return render_template("partials/quota_table.html", results=results, searched_name=name)


if __name__ == '__main__':
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    app.run(host='127.0.0.1', port=5000, debug=True)

'''
Optional: Filter/Search by Status or Expiration Date

You can now write queries like:

SELECT * FROM quota_requests
WHERE status = 'temporary' AND expiration_date < DATE('now');


This would find expired temporary quotas — useful for cleanup tools or alerts.
'''
