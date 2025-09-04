from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_session import Session
import sqlite3
app = Flask(__name__, template_folder='templates',static_folder='static',static_url_path='/')

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

@app.route('/')
def index():
  if "username" in session:
        return redirect(url_for('home'))
  return render_template('index.html')

@app.route('/home')
def home():
      if "username" in session:
        return render_template("layout10.html", username=session['username'])
      return render_template('index.html')

@app.route('/new_complaint')
def new_complaint():
  return render_template('new_complaint.html')

@app.route('/my_complaints')
def my_complaints():
  return render_template('my_complaints.html')

@app.route('/complaint_status')
def complaint_status():
  return render_template('complaint_status.html')

@app.route('/waste_dump')
def waste_dump():
  return render_template('waste_dump.html')

@app.route('/open_drain')
def open_drain():
  return render_template('open_drain.html')

@app.route('/pothole')
def pothole():
  return render_template('pothole.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['usrname']
    password = request.form['paswd']

    res = conn.execute("SELECT password FROM user WHERE username = ?", (username,))
    row = res.fetchone()

    if row and check_password_hash(row[0], password):
        session['username'] = username
        return redirect(url_for('home'))
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
    return redirect(url_for('home'))

# logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ =="__main__":
  create_table()
  app.run(host='0.0.0.0',port=5555,debug=True)