from flask import Flask,render_template, redirect, url_for, request, flash
from app import app
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import logging
import sqlite3


# logging.basicConfig(filename='app_log.log', level=logging.DEBUG,format='%(asctime)s:%(message)s')


@app.route('/')
@app.route('/about')
def index():
    return render_template("index.html")

@app.route('/stream')
def stream():
   return render_template("stream.html")

@app.route('/pay')
def payment():
   return render_template("pay.html")

@app.route('/teams')
def teams():
   return render_template("teams.html")

@app.route('/register_team')
def register_team():
    # conn = sqlite3.connect("test.db")
    # c = conn.cursor()
    # # create_table_for_teams(c,conn)

    # teamname = request.form['name']
    # country = request.form['country']

    # c.execute("INSERT INTO {} VALUES(?, ?)".format("Teams"), (teamname,country))
    # conn.commit()
    return render_template("register_team.html")


@app.route('/team_stats')
def team_stats():
   return render_template("team_stats.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if  username != 'admin' or password != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
    		return render_template("signed_in.html")
    return render_template('login.html', error=error)


class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = ReusableForm(request.form)
 
    print form.errors
    if request.method == 'POST':

        conn = sqlite3.connect("test.db")
        c = conn.cursor()
     
        # create_table_for_users(c,conn)

        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['options']

        if form.validate():
            c.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format("Users"), (name,email,password,role))
            conn.commit()
            return render_template("signed_in.html")
        else:
            flash('Error: All the form fields are required. Mail must be at least 6 chars and the password - at least 3')
    return render_template('register.html', form=form)


def create_table_for_users(c,conn):
    c.execute(""" CREATE TABLE Users(
        id int AUTOINCREMENT,
        name text,
        email text,
        password text,
        role text
    )""")
    conn.commit()


def create_table_for_teams(c,conn):
    c.execute("""
        CREATE TABLE Teams(
        team_name text,
        country text)""")
    conn.commit()