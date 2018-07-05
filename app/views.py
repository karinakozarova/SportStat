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

class RegistrationForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
class TeamsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    country = TextField('Country:',validators=[validators.required()])

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

@app.route('/team_stats')
def team_stats():
   return render_template("team_stats.html")

@app.route('/teams')
def test_route():
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("select team_name from Teams")

    teams = []
    names = []
    countries = []

    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            teams.append(res)
            names.append(res[0])
            stringRes = ''.join(res)

    return render_template('teams.html', teams=teams,names=names,countries = countries,length_teams = len(teams))

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

def coach_or_competitor(username):
    if is_coach(username) == True:
        print "This user is a coach"
        return render_template("signed_in.html",loggedin = True)
    else:
        print "This user is a competitor"
        return render_template("competitor.html", loggedin = True)   

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        database_password = get_password(username)
        unciphered_text = decipher_text(database_password)

        if unciphered_text == password_input:
            is_logged_in = True
            return coach_or_competitor(username)
        else:
            error = 'Invalid Credentials. Please try again.' 
    return render_template('login.html', error=error)
 
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    print form.errors

    if request.method == 'POST':
        conn = sqlite3.connect("test.db")
        c = conn.cursor()
     
        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['options'] # coach - 1, competitor - 2

        ciphered_password = cipher_text(password)

        if form.validate():
            c.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format("Users"), (name,email,ciphered_password,role))
            conn.commit()
            return coach_or_competitor(name)
        else:
            flash('Error: All the form fields are required. Mail must be at least 6 chars and the password - at least 3')
    return render_template('register.html', form=form)


def cipher_text(text_to_cipher):
    """cipers a string

    Args:
        text_to_cipher: the text that should be cipered
    Returns:
        the ciphered text
    """
    string_to_bytes = str.encode(str(text_to_cipher))
    return cipher_suite.encrypt(string_to_bytes)   #required to be bytes 

def decipher_text(text_to_decipher):
    """decipers a string

    Args:
        text_to_decipher: the text that should be decipered
    Returns:
        the unciphered text
    """
    return cipher_suite.decrypt(text_to_decipher)

def create_table_for_users(c,conn):
    """creates the table for the teams
    
    Args:
        c: the cursoer
        conn: the connection to the db
        
    """
    # c.execute("""DROP TABLE Users""")

    c.execute(""" CREATE TABLE Users(
        name text,
        email text,
        password text,
        role text
    )""")
    conn.commit()


def create_table_for_teams(c,conn):
    """creates the table for the teams

    Args:
        c: the cursoer
        conn: the connection to the db
        
    """
    # c.execute("""DROP TABLE Teams""")

    c.execute("""
        CREATE TABLE Teams(
        team_name text,
        country text)""")
    conn.commit()

def get_password(username):
    """gets the password of a user

    Args:
        username: the username for whose password we are looking
    Returns:
        the password stored in the database
        
    """
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("Select password from Users where name = '{}'".format(username))
    res = str(c.fetchone())
    return clean_up_database_str(res)

def is_coach(username):
    """checks if the given username is a coach

    Args:
        username: the username that should be checked

    Returns:
        True if is a coach, False otherwise
        
    """
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("Select role from Users where name = '{}'".format(username))
    res = str(c.fetchone())
    res = clean_up_database_str(res)
    if res == "1": return True
    return False

def clean_up_database_str(str):
    """Removes unneded chars from the string, retrieved from the database

    Args:
        str: the string that should be parsed

    Returns:
        The fixed string

    """
    return str[3:-3] 