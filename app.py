from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_session import Session
import sqlite3

app = Flask(__name__, template_folder='template', static_folder='static', static_url_path='/')

# Database connection
conn = sqlite3.connect('database.db', check_same_thread=False)

def create_table():
    res = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('user',))
    table_exists = res.fetchone()
    if not table_exists:
        conn.execute("CREATE TABLE user (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        conn.commit()

app.secret_key = 'your_secret_key'

# session configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# routes
@app.route('/')
def index():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['usrname']
    password = request.form['paswd']

    res = conn.execute("SELECT password FROM user WHERE username = ?", (username,))
    row = res.fetchone()

    if row and check_password_hash(row[0], password):
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index'))

# register
@app.route('/register', methods=['POST'])
def register():
    username = request.form['usrname']
    password = request.form['paswd']

    res = conn.execute("SELECT username FROM user WHERE username = ?", (username,))
    if res.fetchone():
        return render_template('index.html', error='User already registered')

    newid = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)

    conn.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (newid, username, hashed_password))
    conn.commit()

    session['username'] = username
    return redirect(url_for('dashboard'))

# dashboard
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template("dashboard.html", username=session['username'])
    return redirect(url_for('index'))

# logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    create_table()
    app.run(debug=True)
