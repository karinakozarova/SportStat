from flask import Flask,render_template, redirect, url_for, request, flash
from app import app
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import logging
import sqlite3
from cryptography.fernet import Fernet
import re
import cryptography
from flask_login import current_user, LoginManager, login_user, logout_user, login_required

# logging.basicConfig(filename='app_log.log', level=logging.DEBUG,format='%(asctime)s:%(message)s')
is_logged_in = False
key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
cipher_suite = Fernet(key)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return None


class RegistrationForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
class TeamsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    country = TextField('Country:',validators=[validators.required()])

class CompetitorsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('email:',validators=[validators.required()])
    age = TextField('age:',validators=[validators.required()])
    weight = TextField('weight:',validators=[validators.required()])
    height = TextField('height:',validators=[validators.required()])
    coach = TextField('coach:',validators=[validators.required()])


class User:
    is_authenticated = False
    is_active = True
    is_anonymous = True
    def get_id(self):
        return str(1).encode("utf-8").decode("utf-8") 

    def __init__(self):
        pass

@app.route('/authentication')
def authentication():
    if current_user.is_authenticated:
        print "AUTHENTICAAATED"
    else:
        print "shit.."
    return render_template('under_development.html')

@app.route('/forgotten_password')
def render_underconstruction():
    return render_template('under_development.html')

@login_required
@app.route('/competitor', methods=['GET', 'POST'])
def competitor():
    error = None
    if request.method == 'POST':
        password_input = request.form['submit']
    return render_template('competitors_information.html', error=error)

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

@app.route('/competitors_information', methods=['GET', 'POST'])
def insert_info(name = "Guest", email = "none"):
    form = CompetitorsForm(request.form)
    print form.errors
    if request.method == 'POST':
        print "GEREERERER"
        conn = sqlite3.connect("test.db")
        c = conn.cursor()

        name = request.form['name']
        email = request.form['email']
        age = request.form['age']
        weight = request.form['weight']
        height = request.form['height']
        coach = request.form['coach']

        if form.validate():
           print "VALIDATED"
           print name,email,age,weight,height,coach
        else:
            flash('Error: All the form fields are required.')
        print is_logged_in
    else:
        print "SHIT"
        return render_template("competitors_information.html", verify = False)

@login_required
@app.route('/pay')
def payment():
    return render_template("pay.html")

@login_required
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

@login_required
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
            c.execute("INSERT INTO {} VALUES(?, ?)".format("Teams(team_name,country)"), (name,country))
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
        try:
            unciphered_text = decipher_text(database_password)
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template('login.html', error='Not the right password for that username')
        if unciphered_text == password_input:
            user = User()
            login_user(user)
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
     
        # create_table_for_users(c,conn)
        # create_table_for_teams(c,conn)
        # print "crreated tables"

        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['options'] # coach - 1, competitor - 2
        print "role is " + role


        ciphered_password = cipher_text(password)

        if form.validate() and is_valid_email(email) == True:
            c.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format("Users(name,email,password,role)"), (name,email,ciphered_password,role))
            conn.commit()
            
            print role
            if role == str(2):
                insert_info(name, email)
                # return render_template("competitors_information.html", name = name, email = email,verify = True)
            else:
                print "WTF"
            user = User()
            login_user(user)
        elif is_valid_email == False:
            flash('Error: That is not a valid email address')
        else:
            flash('Error: All the form fields are required. Mail must be at least 6 chars and the password - at least 3')
    return render_template('register.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def is_valid_email(email):
    """checks email against regex

    Args:
        email: the email that should be checked
    Returns:
        True if it's a valid email, False otherwise
    """
    is_valid_email = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
    if is_valid_email is None:
        return False
    return True


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
    c.execute("""DROP TABLE Users""")

    c.execute(""" CREATE TABLE Users(
        id INTEGER PRIMARY KEY,
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
    c.execute("""DROP TABLE Teams""")

    c.execute("""
        CREATE TABLE Teams(
        id INTEGER PRIMARY KEY,
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

def change_password(username, newpassword):
    """changes password in the database of a selected user

    Args:
        username: the username that should be checked
        
    """ 
    conn = sqlite3.connect("test.db")
    c = conn.cursor() 
    password = cipher_text(newpassword)
    c.execute("update Users set password= '{}' where username = {}".format(password,username))
    conn.commit()
 
def clean_up_database_str(str):
    """Removes unneded chars from the string, retrieved from the database

    Args:
        str: the string that should be parsed

    Returns:
        The fixed string

    """
    return str[3:-3] 