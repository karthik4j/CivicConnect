from flask import Flask, render_template, request, redirect, session, url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask,make_response
import uuid
from flask_session import Session
import sqlite3,os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__, template_folder='templates',static_folder='static',static_url_path='/')

#file management
UPLOAD_FOLDER = 'uploads'  # Define your upload directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

# Database connection
conn = sqlite3.connect('database.db', check_same_thread=False)

#---------------------------------------------------------------------------- FUNCTIONS ------------------------------------------------------------------------------------------------
def create_table():
    usr_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('user',))
    comp_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('complaints',))

    usr_table_exists = usr_table_chck.fetchone()
    if not usr_table_exists:
        conn.execute("CREATE TABLE user (id INT PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        conn.commit()

    comp_table_exists = comp_table_chck.fetchone()
    if not comp_table_exists:
        conn.execute("CREATE TABLE complaints (comp_id INTEGER PRIMARY KEY AUTOINCREMENT,complaint TEXT,summary TEXT,location TEXT,imgsrc TEXT,dof DATE,dor DATE,dept TEXT,status INT,id, FOREIGN KEY(id) REFERENCES user(id))")
        conn.commit()

def clean_tuple(tup):
   strings=""
   strings = str(tup)
   strings = strings.replace('(',"")
   strings = strings.replace(')',"")
   strings = strings.replace(',',"")
   return strings


#---------------------------------------------------------------------------- FUNCTIONS ------------------------------------------------------------------------------------------------
app.secret_key = 'your_secret_key'

# session configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/')
def index():
  logged_in_usr_id = request.cookies.get('id')
  if "username" in session and logged_in_usr_id:
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
    logged_in_usr_id = request.cookies.get('id')

    res = conn.execute(
        'SELECT comp_id, complaint, dept, status FROM complaints WHERE id = ?',
        (logged_in_usr_id,)
    )
    result = res.fetchall()   # e.g., [(10, "My car won't start", 'Traffic Management', 0), ...]

    return render_template('my_complaints.html', querry=result)

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
        res = conn.execute("SELECT id FROM user WHERE username = ?", (username,))
        logged_in_usr_id = res.fetchone()
        logged_in_usr_id = clean_tuple(logged_in_usr_id)
        print("current logged in user is: ", logged_in_usr_id)

        # attach cookie to redirect response
        resp = redirect(url_for('home'))
        resp.set_cookie('id', logged_in_usr_id)
        return resp

    else:
        flash('Invalid Username or password', 'error')
        return redirect(url_for('index'))


# register
@app.route('/register', methods=['POST'])
def register():
    username = request.form['usrname']
    password = request.form['paswd']

    res = conn.execute("SELECT username FROM user WHERE username = ?", (username,))
    if res.fetchone():
        flash('User already registered')
        return redirect(url_for('index'))
    else:

      newid = str(uuid.uuid4())
      hashed_password = generate_password_hash(password)

      conn.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (newid, username, hashed_password))
      conn.commit()
      print("saving new user to db")

      session['username'] = username

      # attach cookie to redirect response
      resp = make_response('attach cookie')
      resp.set_cookie('id', newid)
      response =redirect(url_for('index'))
      flash("Account created Successfully")
      print('account creation')
      return response

# logout
@app.route('/logout',methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('id',None)
    response = redirect(url_for('index'))
    response.delete_cookie('id')
    return response

@app.route('/account-page')
def account_page():
   logged_in_usr_id = request.cookies.get('id')
   return render_template('account-page.html',user_id=logged_in_usr_id)

@app.route('/register-complaint', methods=['POST'])
def register_complaint():
    users_complaint = request.form['user_complaint']
    users_location = request.form['user_location']
    dept = request.form['select_dept']
    
    photo = request.files['attached_image']
    if photo and photo.filename != "":
        # Get original extension
        original_filename = secure_filename(photo.filename)
        _, ext = os.path.splitext(original_filename)  # ext will be like ".jpg"
        
        # Generate safe new filename with UUID
        rename = str(uuid.uuid4()) + ext  
        
        # Save file with extension preserved
        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], rename))

    current_datetime = datetime.now()
    # Format the datetime object to YYYY-MM-DD string
    formatted_date = current_datetime.strftime("%Y-%m-%d")
    logged_in_usr_id = request.cookies.get('id')
    conn.execute("INSERT INTO complaints (complaint, location, imgsrc, dof, dept, id,status) VALUES (?, ?, ?, ?, ?, ?, ?)", (users_complaint, users_location, rename,formatted_date,dept,logged_in_usr_id,0))
    conn.commit()
    return render_template('message.html', message='Successfully registered complaint')
    
if __name__ =="__main__":
  create_table()
  app.run(host='0.0.0.0',port=5555,debug=True)