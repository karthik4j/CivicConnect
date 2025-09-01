from flask import Flask,render_template

app = Flask(__name__, template_folder='templates',static_folder='static',static_url_path='/')

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/home')
def home():
  return render_template('layout10.html')

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

if __name__ =="__main__":
  app.run(host='0.0.0.0',port=5555,debug=True)