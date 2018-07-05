from flask import Flask,render_template, redirect, url_for, request, flash
from app import app
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import logging
import sqlite3
from cryptography.fernet import Fernet

# logging.basicConfig(filename='app_log.log', level=logging.DEBUG,format='%(asctime)s:%(message)s')
is_logged_in = False
key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
cipher_suite = Fernet(key)

@app.route('/')
@app.route('/about')
def index():
    return render_template("index.html")

@app.route('/stream')
def stream():
   return render_template("stream.html")

@app.route('/calendar')
def calendar():
   return render_template("calendar.html")

@app.route('/competitors_information')
def insert_info():
    print "is logged in " + str(is_logged_in)
    if is_logged_in == True:
        return render_template("calendar.html")
    else:
        return render_template("not_accessible.html")


@app.route('/pay')
def payment():
    print is_logged_in
    return render_template("pay.html")

@app.route('/teams')
def test_route():

    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("select team_name from Teams")
    teams = []
    names = []
    countries = []
    i = 0
    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            teams.append(res)
            names.append(res[0])
            stringRes = ''.join(res)
        i += 1

    return render_template('teams.html', teams=teams,names=names,countries = countries,legnth = len(teams))

@app.route('/register_team', methods=['GET', 'POST'])
def register_team():
    form = TeamsForm(request.form)
 
    print form.errors
    if request.method == 'POST':
        conn = sqlite3.connect("test.db")
        c = conn.cursor()
     
        name = request.form['name']
        country = request.form['country']

        if form.validate():
            c.execute("INSERT INTO {} VALUES(?, ?)".format("Teams"), (name,country))
            conn.commit()
            is_logged_in = True
        else:
            flash('Error: All the form fields are required.')
        print is_logged_in
    return render_template('register_team.html', form=form)

@app.route('/team_stats')
def team_stats():
   return render_template("team_stats.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        unciphered_text = (cipher_suite.decrypt(get_password(username)))

        if unciphered_text == password_input:
            is_logged_in = True
            if is_coach(username) == True:
                print "is coach"
                return render_template("signed_in.html",loggedin = True)
            else:
                print "is competitor"
                return render_template("competitor.html", loggedin = True)
        else:
            error = 'Invalid Credentials. Please try again.' 
    return render_template('login.html', error=error)


class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
class TeamsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    country = TextField('Country:',validators=[validators.required()])
 
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
        role = request.form['options'] # coach - 1, competitor - 2

        pass_as_bytes = str.encode(str(password))
        ciphered_password = cipher_suite.encrypt(pass_as_bytes)   #required to be bytes




        if form.validate():
            c.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format("Users"), (name,email,ciphered_password,role))
            conn.commit()
            print is_coach(name)
            if is_coach(name) == True:
                print "is coach"
                return render_template("signed_in.html")
            else:
                print "is competitor"
                return render_template("competitor.html", loggedin = True)
        else:
            flash('Error: All the form fields are required. Mail must be at least 6 chars and the password - at least 3')
    return render_template('register.html', form=form)


def create_table_for_users(c,conn):
    c.execute("DROP TABLE Teams")
    c.execute(""" CREATE TABLE Users(
        id int AUTOINCREMENT,
        name text,
        email text,
        password text,
        role text # coach - 1, competitor - 2
    )""")
    conn.commit()


def create_table_for_teams(c,conn):
    c.execute("DROP TABLE Teams")
    c.execute("""
        CREATE TABLE Teams(
        team_name text,
        country text)""")
    conn.commit()


def get_password(username):
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("Select password from Users where name = '{}'".format(username))
    res = str(c.fetchone())
    res = res[3:-3]

    return res

def is_coach(username):
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("Select role from Users where name = '{}'".format(username))
    res = str(c.fetchone())
    res = res[3:-3]
    print res
    if res == "1": return True
    return False