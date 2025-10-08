from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

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
                quota_request TEXT NOT NULL,
                status TEXT DEFAULT 'permanent',
                expiration_date TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Database initialized!")

init_qdb()

def search_quota_requests(name_query):
    """Return all quota requests that match the given name."""
    with sqlite3.connect(QUOTA_DB) as conn:
        cursor = conn.execute("""
            SELECT name, filesystem, ticket_number, quota_request, created_at
            FROM quota_requests
            WHERE name LIKE ?
            ORDER BY created_at DESC
        """, (f"%{name_query}%",))
        return cursor.fetchall()

# --- Helper functions ---
def get_user(username):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username=?", (username,))
        return cursor.fetchone()

def add_user(username, password_hash):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                     (username, password_hash))
        conn.commit()

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
    quota_request = request.form['quota_request']
    status = request.form['status']
    expiration_date = request.form.get('expiration_date') or None  # Can be blank

    with sqlite3.connect(QUOTA_DB) as conn:
        conn.execute("""
            INSERT INTO quota_requests (name, filesystem, ticket_number, quota_request, status, expiration_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, filesystem, ticket_number, quota_request, status, expiration_date))

    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    app.run(host='127.0.0.1', port=5000, debug=True)

'''
🧪 Optional: Filter/Search by Status or Expiration Date

You can now write queries like:

SELECT * FROM quota_requests
WHERE status = 'temporary' AND expiration_date < DATE('now');


This would find expired temporary quotas — useful for cleanup tools or alerts.
'''
