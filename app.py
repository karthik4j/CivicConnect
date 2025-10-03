from flask import Flask, render_template, request, redirect, session, url_for,flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask,make_response
import uuid
from flask_session import Session
import sqlite3,os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory
from transformers import pipeline
summarizer = pipeline("summarization", model="t5-base", tokenizer="t5-base")
import threading

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
    resolution_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('resolution',))

    messages_table_chck = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", ('messages',))

    usr_table_exists = usr_table_chck.fetchone()
    if not usr_table_exists:
        conn.execute("CREATE TABLE user (id TEXT PRIMARY KEY, username TEXT UNIQUE, f_name TEXT,fullname TEXT, l_name TEXT, email TEXT,ph_no INT,DOC DATE, password TEXT)")
        conn.commit()

    comp_table_exists = comp_table_chck.fetchone()
    if not comp_table_exists:
        #here ID maps to the id of the user who filed the complaint.
        conn.execute("CREATE TABLE complaints (comp_id INTEGER PRIMARY KEY AUTOINCREMENT,complaint TEXT,summary TEXT,location TEXT,imgsrc TEXT,dof DATE,dor DATE,dept TEXT,status INT,id, FOREIGN KEY(id) REFERENCES user(id))")
        conn.commit()

    admin_table_exists = admin_table_chck.fetchone()
    if not admin_table_exists:
        conn.execute("CREATE TABLE admin(id TEXT PRIMARY KEY, username TEXT UNIQUE, f_name TEXT, l_name TEXT, fullname TEXT, dept TEXT, email TEXT UNIQUE, password TEXT, DOC DATE, ph_no INT)")
        conn.commit()


    message_table_exists = messages_table_chck.fetchone()
    if not message_table_exists:
        conn.execute("CREATE TABLE messages(msg_id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT,priority TEXT,msg_title TEXT,issue_date DATE, issued_by TEXT, dept TEXT)")
        conn.commit()


    resolution_table_exists = resolution_table_chck.fetchone()
    if not resolution_table_exists:
        conn.execute("""CREATE TABLE IF NOT EXISTS resolution (resolution_id INTEGER PRIMARY KEY AUTOINCREMENT, comp_id INTEGER, admin_id TEXT, user_id TEXT, status INT, msg TEXT, date_of_change DATE, FOREIGN KEY(comp_id) REFERENCES complaints(comp_id) FOREIGN KEY(admin_id) REFERENCES admin(id), FOREIGN KEY(user_id) REFERENCES user(id))""")

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


def start_summary(word,id):
    summary = summarizer(word, max_length=300, min_length=20, do_sample=False)[0]['summary_text']

    res = conn.execute("UPDATE complaints SET summary = ? WHERE imgsrc = ?",(summary,id))
    conn.commit()
    

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


@app.route('/mayor')
def mayor_page():
    return render_template('mayor.html')

@app.route('/secretary')
def secretary_page():
    return render_template('secretary.html')

@app.route('/councilors')
def councilors_page():
    return render_template('councilors.html')

@app.route('/committees')
def committees_page():
    return render_template('committees.html')

@app.route('/departments')
def departments_page():
    return render_template('departments.html')


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

    #function to start summary
    #sumarrized_comp = start_summary(users_complaint)
    thread1 = threading.Thread(target=start_summary, args=(users_complaint,rename))
    thread1.start()

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
    return render_template('admin/admin login.html')

@app.route('/admin_register_page')
def admin_register_page():
    return render_template('admin/admin_register.html')

# admin register
@app.route('/admin_register', methods=['POST'])
def admin_register():
    f_name = request.form['fname']
    l_name = request.form['lname']
    username = request.form['username']
    admin_dept = request.form['department']
    email = request.form['email']
    ph_no = request.form['ph_no']
    password = request.form['password']
    confirm_password = request.form['confirm-password']

    fullname = f_name + " " + l_name
    to_day = get_formatted_date()

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
       "INSERT INTO admin (id, username, f_name, l_name, fullname, dept, email, password, DOC, ph_no ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    (newid, username, f_name, l_name, fullname, admin_dept, email, hashed_password, to_day, ph_no)
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

    return render_template('admin/admin_complaint_view_page.html', querry=result)    

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
    return render_template ('admin/admins_dashboard.html')
    
#view details of admin account by an admin themslef
@app.route('/admin_my_account')
def admin_my_account():
   logged_in_usr_id = request.cookies.get('admin_id')
   res = conn.execute("SELECT username, fullname, dept, email, ph_no, DOC FROM admin WHERE id = ?", (logged_in_usr_id,))
   res = res.fetchone()
   res = clean_tuple(res).split()
 #  print(res)
   
   usr_name = res[0]
    #this is becasue the split function separates the name into two. so we have to add it again to fix this issue
   fullname =res[1] + " " + res[2]
   dept=res[3]
   email =res[4]
   ph_no = res[5]
   DOC = res[6]

   return render_template('admin/admin_view_account.html',user_id=logged_in_usr_id,user_name=usr_name, reg_name=fullname,dept=dept,e_mail=email,ph_no=ph_no,DOC=DOC)


@app.route('/admin_logout',methods=['POST','GET'])
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
    return render_template('admin/admin_issue_notifications.html')

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
    res = conn.execute('SELECT m.msg_title, m.msg, m.priority, a.username, m.dept, m.issue_date FROM messages m JOIN admin a ON m.issued_by = a.id;')
    result = res.fetchall() 
    #print(result)
    return render_template('notifications_user.html',querry=result)

@app.route('/admin_view_complaints/detail/<id>')
def view_detailed_complaints(id):

    res = conn.execute("""SELECT u.fullname, c.complaint, c.location, c.status, c.imgsrc AS src, c.dof, c.summary FROM user u JOIN complaints c ON u.id = c.id WHERE c.comp_id = ?;""",(id,))

    res = res.fetchone()
    #print(res)
    complainant = res[0]
    complaint = res[1]
    location = res[2]
    status = res[3]
    src= res[4]
    DOF = res[5]
    summarized_one = res[6]
   
    return render_template('admin/detailed_complaint_admin.html',comp_id=id,name=complainant,location=location,status=status,src=src,DOF=DOF,complaint=complaint,summary = summarized_one)


@app.route('/admin_view_complaints/show_image/<path:filename>')
def admin_show_image(filename):
    return render_template('admin/show_image.html', filename=filename)


@app.route('/update_complaint_status', methods=['POST'])
def update_complaint_status():
    return render_template('url_for("admin_")')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'uploads'), filename)


@app.route('/update_enquiry_status', methods=['POST'])
def update_enquiry_status():
    if request.is_json:
        data = request.get_json()
        
        # Extract the values from the received JSON data
        comp_id = data.get('comp_id')
        new_status = data.get('status')
        message = data.get('message')
        
        #getting the Admin's ID so that we can use it as a reference for the SQL querry call
        logged_in_adm_id = request.cookies.get('admin_id')

        #fetching the user's ID 
        res = conn.execute("SELECT id FROM complaints WHERE comp_id = ?",(int(comp_id),))
        res = res.fetchone()
        user_id = clean_tuple(res)
        #print("ID of user: ",res," ID of Admin: ",logged_in_usr_id)
        to_day =get_formatted_date()

        # Print the received values to the terminal
        #print(f"Received update for Complaint ID: {comp_id}")
        #print(f"New Status: {new_status}")
        #print(f"Message: '{message}'")

        #need to perform two update operations
        # 1 Update the compalints page with the new status
        cur = conn.execute("UPDATE complaints SET status = ? WHERE comp_id = ?",(new_status, comp_id))

        # 2 Update the message page with the change. (insert operation)
        cur = conn.execute("INSERT INTO resolution (comp_id, admin_id, user_id, status, msg, date_of_change) VALUES(?, ?, ?, ?, ?, ?)",(comp_id, logged_in_adm_id, user_id, new_status, message, to_day))
        conn.commit()

        # Return a success response
        return jsonify({'message': 'Status and message received successfully', 'status_received': new_status}), 200
    
    # Handle non-JSON requests
    return jsonify({'error': 'Request must be JSON'}), 400

if __name__ =="__main__":
  create_table()
  app.run(host='0.0.0.0',port=5555,debug=True)

