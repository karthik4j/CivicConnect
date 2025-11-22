from flask import Flask, render_template, request, redirect, session, url_for,flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask,make_response
import uuid
from flask_session import Session
import sqlite3,os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory
import threading
import string,random
#3rd party intergration
from twilio.rest import Client
from dotenv import load_dotenv
from pathlib import Path
#---------------------------
#libraries for AI part:---------------------------------------------------------------
from transformers import pipeline
import pandas as pd
from datasets import Dataset
from sklearn.model_selection import train_test_split
import pandas as pd
from datasets import Dataset
from sklearn.model_selection import train_test_split
#--------------------------------------------- Ai SUMMARIZER PART------
summarizer = pipeline("summarization", model="t5-base", tokenizer="t5-base")
#---------------------------------------------------------------------------------------

app = Flask(__name__, template_folder='templates',static_folder='static',static_url_path='/')

#file management
UPLOAD_FOLDER = 'uploads'  # Define your upload directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

# Database connection
conn = sqlite3.connect('database.db', check_same_thread=False)
#-----------------------         twilio ----------------------------------------------------

# Find the venv folder relative to this file
base_dir = Path(__file__).resolve().parents[0]  # adjust if needed
#print(base_dir)
venv_env = base_dir / ".env" / ".env"

# Load .env from inside venv
load_dotenv(venv_env)

def format_indian_number(num_str: str) -> str:

    # Keep only digits
    digits = "".join(filter(str.isdigit, num_str))

    # Case 1: Already includes country code (91)
    if digits.startswith("91") and len(digits) == 12:
        return "+" + digits

    # Case 2: Only 10-digit local Indian number
    if len(digits) == 10:
        return "+91" + digits

    # If none match, error out
    raise ValueError(f"Invalid Indian phone number: {num_str}")


def send_message(number: str, text: str):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_PHONE_NUMBER")

    client = Client(account_sid, auth_token)

    twilio_msg = client.messages.create(
        body=text,
        from_=from_number,
        to=format_indian_number(number),
    )

    print("Sent:", twilio_msg.body)


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

@app.route('/user_forgot')
def user_forgot():
    session['user_type']={'type':"user"}
    return render_template('reset_user_pass.html')

@app.route('/admin_forgot')
def admin_forgot():
    session['user_type']={'type':"admin"}
    return render_template('reset_user_pass.html')

@app.route('/user_forgot_back')
def user_forgot_back():
    session.clear()
    return redirect(url_for('index'))

@app.route('/check_number_OTP', methods=['POST'])
def check_number_OTP():
    data = request.get_json()
    ph_no = data.get('ph_no')
    #print(ph_no)
    usr_type = session.pop('user_type') 
    usr_type = usr_type['type']
    print('Who is: ',usr_type)

    if(usr_type == 'user'):
        
        id = conn.execute('SELECT id FROM user WHERE ph_no = ?',(ph_no,))
        id = id.fetchone()
        id = clean_tuple(id)
        print('ID of user: ',id)
        if id=='None':
            resp = jsonify({'status':'NOT','message':'Invalid phone number'})
            session['user_type']={'type':usr_type}
        else:
            resp = jsonify({'status':'OK','message':None})
            otp_now = generate_otp_choice()
            session['user_type']={'type':"user",'id':id,'otp':otp_now}
            print('OTP generated : ',otp_now)
        return resp
        
    elif(usr_type == 'admin'):
        id = conn.execute('SELECT id FROM admin WHERE ph_no = ?',(ph_no,))
        id = clean_tuple(id.fetchone())
        print('ID of admin: ',id)
        if id=='None':
            resp = jsonify({'status':'NOT','message':'Invalid phone number'})
            session['user_type']={'type':usr_type}
        else:
            otp_now = generate_otp_choice()
            resp = jsonify({'status':'OK','message':None})
            session['user_type']={'type':"admin",'id':id,'otp':otp_now}
            print('OTP generated : ',otp_now)
        return resp
    else:
        print("error")
        resp = jsonify({'message':"Error with resetting, redireting to homepage",'url':url_for('index')})
        return resp
    
@app.route('/verfiy_OTP_sent',methods=(['POST']))
def verfiy_OTP_sent():
    data = request.get_json()
    given_OTP =int(data['otp'])

    expected = int(session.get('user_type')['otp'])
    print('OTP sent : ',given_OTP)

    if(expected == given_OTP):
        resp = jsonify({'message':"OK"})
    else:
        resp = jsonify({'message':"NOT"})
    return resp

@app.route('/set-new-password',methods=['POST'])
def set_new_password():
    data = request.get_json()
    new_password = data['password']
    usr_session = session.pop('user_type')
    usr_type = usr_session['type']
    usr_id = usr_session['id']

    print("New password: ",new_password)
    print('ID : ',usr_id)

    if usr_type == 'user':
        res = conn.execute('SELECT id from user WHERE id = ?',(usr_id,))
        if res.fetchone():
            res = conn.execute('UPDATE user SET password = ? WHERE id = ?',(generate_password_hash(new_password),usr_id, ))
            conn.commit()
            resp = jsonify({'message':'OK','redirect':url_for('index')})
        else:
            resp = jsonify({'message':'NOT'})
        return resp
    
    elif usr_type == 'admin':
        res = conn.execute('SELECT id from admin WHERE id = ?',(usr_id,))
        if res.fetchone():
            res = conn.execute('UPDATE admin SET password = ? WHERE id = ?',(generate_password_hash(new_password),usr_id, ))
            conn.commit()
            resp = jsonify({'message':'OK','redirect':url_for('admin_login')})
        else:
            resp = jsonify({'message':'NOT'})
        return resp
    else:
        resp = resp = jsonify({'message':'Server error, try again'})
        return resp


@app.route('/home')
def home():
      if "username" in session:
        return render_template("user_dashboard.html", username=session['username'])
      return render_template('index.html')

@app.route('/mayor')
def mayor_page():
    return render_template('mayor.html')

@app.route('/user_dashboard_page')
def user_dashboard_page():
    return render_template('user_dashboard.html')

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

@app.route('/help_user')
def help_user():
    return render_template('help.html')

#todo need to make the webiste here.
@app.route('/complaints/<id>')
def view_detailed_complaints_usr(id):
    res =conn.execute("""SELECT 
c.dof AS complaint_date,
    c.complaint,
    c.status AS complaint_status,
    r.msg AS admin_response,
    a.dept AS admin_department,
    a.fullname AS admin_name,
    r.date_of_change AS response_date
FROM complaints c
LEFT JOIN (
    SELECT res.*
    FROM resolution res
    INNER JOIN (
        SELECT comp_id, MAX(date_of_change) AS latest_date
        FROM resolution
        GROUP BY comp_id
    ) latest_res
    ON res.comp_id = latest_res.comp_id AND res.date_of_change = latest_res.latest_date
) r ON c.comp_id = r.comp_id
LEFT JOIN admin a ON r.admin_id = a.id
WHERE c.comp_id = ?;
""", (id,))

# fetch result
    result = res.fetchone()

    """
    if result:
        print("Complaint Date:", result[0])
        print("Complaint:", result[1])
        print("Status:", result[2])
        print("Admin Response:", result[3])
        print("Admin Department:", result[4])
        print("Admin Name:", result[5])
        print("Response Date:", result[6])
    else:
        print("No complaint found for that ID.")
    """
    return render_template('view_detailed_complaints_user.html',complaint_id=id,issue_date=result[0],status=result[2],complaint=result[1],response=result[3],dept=result[4],officer_name=result[5],updated_date=result[6])

@app.route('/complaint_status')
def complaint_status():
  
  logged_in_usr_id = request.cookies.get('id')
  res = conn.execute('SELECT comp_id, dof, complaint, status FROM complaints WHERE id = ?',(logged_in_usr_id, ))
  res = res.fetchall()

  return render_template('complaint_status.html',complaints=res)

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


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('usrname')
    password = data.get('paswd')
    f_name = data.get('fname')
    l_name = data.get('lname')
    ph_no = data.get('phone')

    res = conn.execute("SELECT username FROM user WHERE username = ?", (username,))
    if res.fetchone():
        return "User already registered", 400
    
    res = conn.execute("SELECT ph_no FROM user WHERE ph_no =?",(ph_no,))
    if res.fetchone():
        return "Phone number already registered", 400

    # Temporary Storage in Session
    full_name = f_name + " " + l_name
    hashed_password = generate_password_hash(password)
    otps = generate_otp_choice()

    #ONLY FOR RESTING REMOVE
    print("generated OTP: ",otps)
    msg_user = f"""Your OTP for CivicConnect is {otps}"""
    print(msg_user)

    #warning this will send an actual message. 
    #send_message(format_indian_number(ph_no),msg_user)

    session['temp_user_data'] = {
        'id': str(uuid.uuid4()), # Generate ID now
        'username': username,
        'f_name': f_name,
        'l_name': l_name,
        'fullname': full_name,
        'ph_no': ph_no,
        'password': hashed_password,
        'DOC': get_formatted_date(), # Date of Creation
        'OTP':otps
    }
    
    
    #Respond with Redirect URL (to Stage 2 form)
    response_data = {
        'message': 'Initial data received, proceeding to additional details.',
        'redirect_url': url_for('start_tfa') 
    }
    
    # We do NOT set the 'id' cookie yet, as registration isn't final
    resp = make_response(jsonify(response_data), 200) 
    return resp

def generate_otp_choice():
    otp_integer = random.randint(100000, 999999)
    return otp_integer

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    received_otp = int(data.get('otp'))
    
    expected_otp = session.get('temp_user_data')['OTP']
    print("Expected OTP",expected_otp,type(expected_otp))
    print("Recived OTP",received_otp,type(received_otp))

    
    if received_otp and expected_otp and received_otp == expected_otp:
        
        # You can now proceed to store the user's final data (which happens in finalize_registration).
        return jsonify({
            "success": True, 
            "message": "Verification successful! You will be logged in shortly."
        }), 200
    else:
        # OTP is invalid
        return jsonify({
            "success": False, 
            "message": "Invalid OTP. Please check your phone and try again."
        }), 200

@app.route('/finalize_registration', methods=['POST'])
def finalize_registration():    
    #Retrieve temporary data from session
    temp_data = session.pop('temp_user_data', None)
    print("Final save")

    if not temp_data:
        # User tried to access this route without starting registration
        return "Registration session expired or invalid.", 403

    #Combine Data and Insert into DB
    insertion_tuple = (
        temp_data['id'], 
        temp_data['username'], 
        temp_data['f_name'], 
        temp_data['l_name'], 
        temp_data['fullname'], 
        temp_data['DOC'], 
        temp_data['ph_no'], 
        temp_data['password']
        # Add new fields here if you update the SQL query
    )
    try:
        # Database insertion (Finally)
        conn.execute(
            "INSERT INTO user (id, username, f_name, l_name, fullname, DOC, ph_no, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
            insertion_tuple
        )
        conn.commit()

        #Finalize Session/Cookies
        session['username'] = temp_data['username']
        
        redirect_url = url_for('user_dashboard_page') 
        
        # Return a JSON object containing the status and the redirect URL
        resp = jsonify({
            "success": True, 
            "message": "Account created Successfully. Redirecting...",
            "redirect_to": redirect_url
        })
        
        # Set cookie on the response object
        resp.set_cookie('id', temp_data['id'])
        return resp
        
    except Exception as e:
        # Handle database errors
        print(f"Database error during finalization: {e}")
        return jsonify({"success": False, "message": "A database error occurred during registration."}), 500

@app.route('/user_reg_page')
def user_reg_page():
    return render_template('user-registration-page.html')

#internal use only
@app.route('/start_tfa')
def start_tfa():
    return render_template('two-fa.html')

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
    #thread2 = threading.Thread(target=predict_department, args=(users_complaint,rename))
    thread1.start()
    #thread2.start()

    return render_template('message.html', message='Successfully registered complaint')

    
@app.route('/admin_login')
def admin_login():
    return render_template('admin/admin login.html')

@app.route('/admin_register_page')
def admin_register_page():
    return render_template('admin/admin_register.html')

# admin register
@app.route('/admin_register', methods=['POST'])
def admin_register():
    # Ensure request content type is application/json
    if not request.is_json:
        return "Unsupported media type", 415

    data = request.get_json()
    
    # FIX: Corrected dictionary access (used parentheses instead of brackets)
    f_name = data.get('fname')
    l_name = data.get('lname')
    username = data.get('usrname') # Matches payload key from HTML
    admin_dept = data.get('dept')
    email = data.get('email')
    ph_no = data.get('phone')
    password = data.get('paswd')
    # confirm_password = data.get('cpass') # Not needed, handled client-side/removed from logic

    # Basic validation checks
    if not all([f_name, l_name, username, admin_dept, email, ph_no, password]):
        return "Missing required field data.", 400

    fullname = f_name + " " + l_name
    to_day = get_formatted_date()

    # --- Error Checks (FIXED to return 400 status) ---
    # check if username already exists
    res = conn.execute("SELECT username FROM admin WHERE username = ?", (username,))
    if res.fetchone():
        return "Username already taken. Try a different one.", 400 # FIX: Returning 400 error

    # check if email already exists
    res = conn.execute("SELECT email FROM admin WHERE email = ?", (email,))
    if res.fetchone():
        return "Email already registered. Use a different email.", 400 # FIX: Returning 400 error
    
    #check if the phone_no is already registed to someone else
    res = conn.execute("SELECT ph_no from admin WHERE ph_no = ?",(ph_no, ))
    if res.fetchone():
        return "Phone number already registered. Please enter a new number.", 400 # FIX: Returning 400 error
    # --- End Error Checks ---

    # create new admin
    newid = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)
    
    #generate OTP
    otps = generate_otp_choice()

    #send OTP
    print("generated OTP: ",otps) #remove 
    msg_user = f"""Your OTP for CivicConnect is {otps}"""
    print(msg_user)

    #warning this will send an actual message. 
    #send_message(format_indian_number(ph_no),msg_user)

    # temprarily store session
    session['temp_admin'] = {
        'id':newid,
        'username':username,
        'f_name':f_name,
        'l_name':l_name,
        'fullname':fullname,
        'dept':admin_dept,
        'email':email,
        'password':hashed_password,
        'DOC':to_day,
        'ph_no':ph_no,
        'otp':otps # Storing OTP in session
    }

    #Respond with Redirect URL (to Stage 2 form)
    response_data = {
        'message': 'Initial data received, proceeding to additional details.',
        'redirect_url': url_for('start_tfa_adm') 
    }
    
    # We do NOT set the 'id' cookie yet, as registration isn't final
    resp = make_response(jsonify(response_data), 200) 
    return resp

@app.route('/start_tfa_adm')
def start_tfa_adm():
    return render_template('admin/two-fa-adm.html')

@app.route('/verify_otp_adm', methods=['POST'])
def verify_otp_adm():
    data = request.get_json()
    received_otp = int(data.get('otp'))
    
    expected_otp = session.get('temp_admin')['otp']
    print("Expected OTP",expected_otp,type(expected_otp))
    print("Recived OTP",received_otp,type(received_otp))

    
    if received_otp and expected_otp and received_otp == expected_otp:
        
        # You can now proceed to store the user's final data (which happens in finalize_registration).
        return jsonify({
            "success": True, 
            "message": "Verification successful! You will be logged in shortly."
        }), 200
    else:
        # OTP is invalid
        return jsonify({
            "success": False, 
            "message": "Invalid OTP. Please check your phone and try again."
        }), 200

@app.route('/finalize_admin_registration', methods=['POST'])
def finalize_admin_registration():
    # Retrieve temporary data from session using the key set in /admin_register
    temp_data = session.pop('temp_admin', None)
    print("Admin Final Save Attempt")

    if not temp_data:
        # User tried to access this route without completing the OTP stage
        return "Admin registration session expired or invalid.", 403

    # Extract data for database insertion
    newid = temp_data['id']
    username = temp_data['username']
    admin_dept = temp_data['dept']

    # Combine Data and Insert into DB
    insertion_tuple = (
        temp_data['id'],
        temp_data['username'],
        temp_data['f_name'],
        temp_data['l_name'],
        temp_data['fullname'],
        temp_data['dept'],
        temp_data['email'],
        temp_data['password'], # Hashed password
        temp_data['DOC'],
        temp_data['ph_no']
    )
    
    try:
        # Database insertion (Finally)
        # Using the exact SQL provided in your request
        conn.execute(
            "INSERT INTO admin (id, username, f_name, l_name, fullname, dept, email, password, DOC, ph_no) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            insertion_tuple
        )
        conn.commit()

        # Finalize Session/Cookies
        session['username'] = username
        
        # Set the redirect URL to the admin login or dashboard page
        redirect_url = url_for('admin_dashboard') 
        
        # Return a JSON object containing the status and the redirect URL
        response_data = {
            "success": True, 
            "message": "Admin account created successfully 🎉. Redirecting...",
            "redirect_to": redirect_url
        }

        resp = make_response(jsonify(response_data), 200)
        
        # Set cookies on the response object
        resp.set_cookie('admin_id', newid)
        resp.set_cookie('dept', admin_dept)
        
        print(f"New admin '{username}' saved to db and session/cookies set.")
        return resp
        
    except Exception as e:
        # Handle database errors
        print(f"Database error during admin finalization: {e}")
        # Note: If the session was popped successfully, you might want to re-add it 
        # or handle rollback, but for simplicity, we return a 500 error.
        return jsonify({"success": False, "message": "A database error occurred during registration."}), 500


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
    pending_count = conn.execute("SELECT COUNT(status) FROM complaints  WHERE status = 0")
    in_prog_count = conn.execute("SELECT COUNT(status)FROM complaints  WHERE status = 1 ")
    resolved_count = conn.execute("SELECT COUNT(status) FROM complaints  WHERE status = 2")
    #print("Pending :",clean_tuple(pending_count.fetchone()))
    #print("in_prog_count :",clean_tuple(in_prog_count.fetchone()))
    #print("resolved_count :",clean_tuple(resolved_count.fetchone()))

    pending_count = clean_tuple(pending_count.fetchone())
    in_prog_count = clean_tuple(in_prog_count.fetchone())
    resolved_count = clean_tuple(resolved_count.fetchone())

    return render_template ('admin/admins_dashboard.html',pending=pending_count,resolved=resolved_count,progress=in_prog_count)
    
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
    notification_ward = request.form['ward2']
    #print(notification_info,notification_title,notification_priority)

    to_day = get_formatted_date()
    adm_id = request.cookies.get('admin_id')
    adm_dept = request.cookies.get('dept')

    conn.execute("INSERT INTO messages (ward , msg , priority, msg_title, issue_date, issued_by, dept) VALUES (?, ?, ?, ?, ?, ?, ?)",(notification_ward,notification_info,notification_priority,notification_title,to_day,adm_id,adm_dept))
    conn.commit()

    
    #flash("Message sent",'success')
    return render_template('admin/admin_issue_notifications.html')

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

