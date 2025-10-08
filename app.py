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
def init_db():
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

init_db()

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

if __name__ == '__main__':
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    app.run(host='127.0.0.1', port=5000, debug=True)
