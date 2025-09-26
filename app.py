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
    admin_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('admin',))

    messages_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('messages',))

    usr_table_exists = usr_table_chck.fetchone()
    if not usr_table_exists:
        conn.execute("CREATE TABLE user (id TEXT PRIMARY KEY, username TEXT UNIQUE, f_name TEXT,fullname TEXT, l_name TEXT, email TEXT,ph_no INT,DOC DATE, password TEXT)")
        conn.commit()

    comp_table_exists = comp_table_chck.fetchone()
    if not comp_table_exists:
        conn.execute("CREATE TABLE complaints (comp_id INTEGER PRIMARY KEY AUTOINCREMENT,complaint TEXT,summary TEXT,location TEXT,imgsrc TEXT,dof DATE,dor DATE,dept TEXT,status INT,id, FOREIGN KEY(id) REFERENCES user(id))")
        conn.commit()

    admin_table_exists = admin_table_chck.fetchone()
    if not admin_table_exists:
        conn.execute("CREATE TABLE admin (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT UNIQUE,f_name TEXT,dept TEXT)")
        conn.commit()


    message_table_exists = messages_table_chck.fetchone()
    if not message_table_exists:
        conn.execute("CREATE TABLE messages(msg_id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT,priority TEXT,msg_title TEXT,issue_date DATE, issued_by TEXT, dept TEXT)")
        conn.commit()

def clean_tuple(tup):
   strings=""
   strings = str(tup)
   strings = strings.replace('(',"")
   strings = strings.replace(')',"")
   strings = strings.replace(',',"")
   strings = strings.replace("'","")
   return strings

#returns the current data in a formatted string
def get_formatted_date():

    current_datetime = datetime.now()
    # Format the datetime object to YYYY-MM-DD string
    formatted_date = current_datetime.strftime("%Y-%m-%d")
    return formatted_date

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
        return render_template("user_dashboard.html", username=session['username'])
      return render_template('index.html')

@app.route('/new_complaint')
def new_complaint():
  return render_template('new_complaint.html')

@app.route('/my_complaints')
def my_complaints():
    logged_in_usr_id = request.cookies.get('id')

    res = conn.execute(
        'SELECT comp_id, complaint, dept, status FROM complaints WHERE id = ?',
        (logged_in_usr_id.replace("'",""),)
    )
    result = res.fetchall()   # e.g., [(10, "My car won't start", 'Traffic Management', 0), ...]

    return render_template('my_complaints.html', querry=result)

@app.route('/complaint_status')
def complaint_status():
  return render_template('complaint_status.html')

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
    data = request.get_json()
    username = data.get('usrname')
    password = data.get('paswd')
    f_name = data.get('fname')
    l_name = data.get('lname')
    ph_no = data.get('phone')

    full_name = f_name + " " + l_name
    to_day = get_formatted_date()

    res = conn.execute("SELECT username FROM user WHERE username = ?", (username,))
    if res.fetchone():
        return "User already registered", 400
    else:
        newid = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)

        conn.execute("INSERT INTO user (id, username, f_name, l_name, fullname, DOC, ph_no, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                     (newid, username, f_name, l_name, full_name, to_day, ph_no, hashed_password))
        conn.commit()

        session['username'] = username
        resp = make_response("Account created Successfully")
        resp.set_cookie('id', newid)
        return resp

@app.route('/user_reg_page')
def user_reg_page():
    return render_template('user-registration-page.html')

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
   res = conn.execute("SELECT username, fullname, ph_no , DOC  FROM user WHERE id = ?", (logged_in_usr_id,))
   res = res.fetchone()
   res = clean_tuple(res).split()
   print(res)
   
   usr_name = res[0]
   fullname = res[1] +" "+ res[2]
   ph_no = res[3]
   DateOfCreation = res[4]
   
   return render_template('account-page.html',user_id=logged_in_usr_id,user_name=usr_name, reg_name=fullname, ph_no=ph_no,DOC=DateOfCreation)

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

    formatted_date = get_formatted_date()

    logged_in_usr_id = request.cookies.get('id')
    conn.execute("INSERT INTO complaints (complaint, location, imgsrc, dof, dept, id,status) VALUES (?, ?, ?, ?, ?, ?, ?)", (users_complaint, users_location, rename,formatted_date,dept,logged_in_usr_id.replace("'",""),0))
    conn.commit()
    return render_template('message.html', message='Successfully registered complaint')

#spot waste dump
@app.route('/waste_dump')
def waste_dump():
    return render_template('spot_waste_dump.html')

#spot open drain
@app.route('/open_drain')
def open_drain():
    return render_template('spot_open_drain.html')

#spot pothole
@app.route('/pothole')
def pothole():
    return render_template('spot_pothole.html')
    
@app.route('/admin_login')
def admin_login():
    return render_template('admin login.html')

@app.route('/admin_register_page')
def admin_register_page():
    return render_template('admin_register.html')

# admin register
@app.route('/admin_register', methods=['POST'])
def admin_register():
    fullname = request.form['fullname']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm-password']
    admin_dept = request.form['department']

    # check password match (extra server-side validation)
    if password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for('admin_login'))  # render form again

    # check if username already exists
    res = conn.execute("SELECT username FROM admin WHERE username = ?", (username,))
    if res.fetchone():
        flash("Username already taken. Try a different one.")
        return redirect(url_for('admin_login'))

    # check if email already exists
    res = conn.execute("SELECT email FROM admin WHERE email = ?", (email,))
    if res.fetchone():
        flash("Email already registered. Use a different email.")
        return redirect(url_for('admin_login'))

    # create new admin
    newid = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)

    conn.execute(
        "INSERT INTO admin (id, username, password, email, f_name,dept) VALUES (?, ?, ?, ?, ?, ?)",
        (newid, username, hashed_password, email, fullname, admin_dept)
    )
    conn.commit()

    # start session
    session['admin_username'] = username  

    # attach cookie
    resp = make_response(redirect(url_for('admin_login')))  # redirect after success
    resp.set_cookie('admin_id', newid)
    resp.set_cookie('dept',admin_dept)

    flash("Admin account created successfully 🎉")
    print("New admin saved to db")

    return resp

#route for fetching complaints from the DB (full view)
@app.route('/admin_view_complaints')
def admin_view_complaints():
    #order complaint_id, dof, person's name, status, dept, location
    res = conn.execute('SELECT c.comp_id, c.dof, u.username, c.status, c.dept, c.location, c.complaint FROM complaints c JOIN user u ON c.id = u.id')
    result = res.fetchall() 
   # print(result)

    return render_template('admin_complaint_view_page.html', querry=result)    

@app.route('/admin_cred_check', methods=['POST'])
def admin_cred_check():
    username = request.form['username']
    password = request.form['password']

    # fetch hashed password for the admin
    res = conn.execute("SELECT password FROM admin WHERE username = ?", (username,))
    row = res.fetchone()

    if row and check_password_hash(row[0], password):
        # store session info
        session['admin_username'] = username

        # get admin id
        res = conn.execute("SELECT id FROM admin WHERE username = ?", (username,))
        logged_in_admin_id = res.fetchone()
        logged_in_admin_id = clean_tuple(logged_in_admin_id)
        print("current logged in admin is:", logged_in_admin_id)

        # get dept id
        res = conn.execute("SELECT dept FROM admin WHERE username = ?", (username,))
        logged_in_admin_dept = res.fetchone()
        logged_in_admin_dept = clean_tuple(logged_in_admin_dept)
        print("current dept:", logged_in_admin_dept)

        # attach cookie to response
        resp = redirect(url_for('admin_dashboard'))  # you should have this route
        resp.set_cookie('admin_id', logged_in_admin_id)
        resp.set_cookie('dept',logged_in_admin_dept)
        return resp

    else:
        flash('Invalid Admin Username or Password', 'error')
        return redirect(url_for('admin_login'))  # go back to admin login page

#admin dashboard 
@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template ('admins_dashboard.html')
    

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_username', None)
    session.pop('admin_id',None)
    response = redirect(url_for('admin_login'))
    response.delete_cookie('admin_id')
    response.delete_cookie('dept')
    return response

#@app.route('/fetch_complaints_admin')
#def fetch_complaints_admin():

@app.route('/admin_issue_notifications_page' )
def admin_issue_notifications_page():
    return render_template('admin_issue_notifications.html')

@app.route('/update_notifications_admin', methods=['POST'])
def update_notifications_admin():
    notification_info = request.form['message']
    notification_title = request.form['notification_name']
    notification_priority = request.form['priority']
    
    #print(notification_info,notification_title,notification_priority)

    to_day = get_formatted_date()
    adm_id = request.cookies.get('admin_id')
    adm_dept = request.cookies.get('dept')

    conn.execute("INSERT INTO messages (msg , priority, msg_title, issue_date, issued_by, dept) VALUES (?, ?, ?, ?, ?, ?)",(notification_info,notification_priority,notification_title,to_day,adm_id,adm_dept))
    conn.commit()

    
    #flash("Message sent",'success')
    return render_template('admin_issue_notifications.html')

@app.route('/get_notifications_all')
def get_notifications_all():
    res = conn.execute('SELECT m.msg_id, m.msg, m.priority, a.username, m.dept, m.issue_date FROM messages m JOIN admin a ON m.issued_by = a.id;')
    result = res.fetchall() 
    #print(result)
    return render_template('notifications_user.html',querry=result)

if __name__ =="__main__":
  create_table()
  app.run(host='0.0.0.0',port=5555,debug=True)
