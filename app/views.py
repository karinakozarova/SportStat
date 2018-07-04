from flask import Flask,render_template, redirect, url_for, request, flash
from app import app
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField

import sqlite3



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


class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
@app.route("/register", methods=['GET', 'POST'])
def hello():


    form = ReusableForm(request.form)
 
    print form.errors
    if request.method == 'POST':
        conn = sqlite3.connect("test.db")
        c = conn.cursor()

        name=request.form['name']
        password=request.form['password']
        email=request.form['email']
        print name, " ", email, " ", password



        if form.validate():
            c.execute("INSERT INTO {} VALUES(?, ?, ?)".format("Users"), (name,email,password))
            flash('Successfully registered! ' + name + password + email)
            conn.commit()
            conn.close()

            flash('Thanks for registration ' + name)
            return render_template("signed_in.html")
        else:
            flash('Error: All the form fields are required.')
            
    conn.close()
    return render_template('register.html', form=form)



