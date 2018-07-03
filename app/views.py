from flask import Flask,render_template, redirect, url_for, request
from app import app


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("index.html")


@app.route('/hello')
def hello_world():
   return render_template("hello.html")


@app.route('/stream')
def stream():
   return render_template("stream.html")

@app.route('/pay')
def payment():
   return render_template("pay.html")

@app.route('/teams')
def teams():
   return render_template("teams.html")


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
    	# hardcoded values for username and password
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
    		return render_template("signed_in.html")
    return render_template('login.html', error=error)
