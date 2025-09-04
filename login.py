from flask import Flask, render_template,redirect,request
app = Flask(__name__,template_folder='templates',static_folder='static',static_url_path='/')

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/home')
def home():
  return render_template('layout10.html')

if __name__ in  "__main__":
  app.run(debug=True)