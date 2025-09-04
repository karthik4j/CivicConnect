from flask import Flask, render_template,request,redirect,session,url_for
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy 

app = Flask(__name__,template_folder='template',static_folder='static',static_url_path='/')
app.secret_key = 'your_secret_key'

#configuring SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db = SQLAlchemy(app)

#database model #single row in the database 
class User(db.Model):
  #class variables here
  id = db.Column(db.Integer,primary_key =True)
  username = db.Column(db.String(25),unique=True,nullable=False)
  password_hash = db.Column(db.String(20),nullable=False)

  def set_password(self, password):
    self.password_hash = generate_password_hash(password)
    

  def check_password(self, password):
    return check_password_hash(self.password_hash,password)

#routes
@app.route('/')
def index():
  if "username" in session:
    return redirect(url_for('dashboard'))
  return render_template('index.html')

#login
@app.route('/login',methods=['POST'])
def login():
  #collect the info from the form. Check if it is in the db. Otherwise, don't let them login and redirect to home page
  username = request.form['usrname']
  pasword = request.form['paswd']

  user = User.query.filter_by(username=username).first()
  if user and user.check_password(pasword):
    session['username']=username
    return redirect(url_for('dashboard'))

  else:
     return redirect(url_for('index'))
  
#register
@app.route('/register',methods=['POST'])
def register():
  username = request.form['usrname']
  pasword = request.form['paswd']
  user = User.query.filter_by(username=username).first()
  if user:
    return render_template('index.html',error='already registered')
  else:
    new_user = User(username=username)
    new_user.set_password(pasword)
    db.session.add(new_user)
    db.session.commit()
    session['username'] = username
    return redirect(url_for('dashboard'))
  
#dashboard
@app.route('/dashboard')
def dashboard():
  if "username" in session:
    return render_template("dashboard.html",username=session['username'])
  return redirect(url_for('index'))

#logout
@app.route('/logout')
def logout():
  session.pop('username',None)
  return redirect(url_for('index'))
if __name__ == "__main__":
  with app.app_context():
    db.create_all()
  app.run(debug=True)