""" 
------------------------------------------------------------------------
                        IMPORTS SECTION
------------------------------------------------------------------------
"""

from flask import Flask,render_template, redirect, url_for, request, flash
from app import app
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import logging
import sqlite3
import re

from flask_login import current_user, LoginManager, login_user, logout_user, login_required

# for passwords encryption
"""

    AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
    HMAC using SHA256 for authentication.
    Initialization vectors are generated using os.urandom().
"""
import base64
import os
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# logging.basicConfig(filename='app_log.log', level=logging.DEBUG,format='%(asctime)s:%(message)s')

""" 
------------------------------------------------------------------------
                      GLOBAL VARIABLES SECTION
------------------------------------------------------------------------
"""
is_logged_in = False
key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
cipher_suite = Fernet(key)

login_manager = LoginManager()
login_manager.init_app(app)

database_name = "test.db"

@login_manager.user_loader
def load_user(user_id):
    return None



""" 
------------------------------------------------------------------------
                            FORMS SECTION
------------------------------------------------------------------------
"""
class RegistrationForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
 
class TeamsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    coach = TextField('Coach:',validators=[validators.required()])
    country = TextField('Country:',validators=[validators.required()])

class CompetitorsForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:',validators=[validators.required()])
    age = TextField('Age:',validators=[validators.required(),validators.Length(min=1, max=3)])
    weight = TextField('Weight:',validators=[validators.required(),validators.Length(min=2, max=4)])
    height = TextField('Height:',validators=[validators.required(),validators.Length(min=2, max=4)])
    teamname = TextField('Teamname:',validators=[validators.required()])


""" 
------------------------------------------------------------------------
                            CLASSES SECTION
------------------------------------------------------------------------
"""
class User:
    is_authenticated = False
    is_active = True
    is_anonymous = True
    def get_id(self):
        return str(1).encode("utf-8").decode("utf-8") 

    def __init__(self):
        pass

""" 
------------------------------------------------------------------------
                            ROUTES SECTION
------------------------------------------------------------------------
"""
@app.route('/')
@app.route('/about')
def index():
    return render_template("index.html")

@app.route('/stream')
def stream():
   return render_template("stream.html")

@login_required
@app.route('/new_event', methods=['GET', 'POST'])
def create_event():
    return render_template("new_event.html")

@app.route('/calendar')
def calendar():
   conn = sqlite3.connect(database_name)
   c = conn.cursor()


   return render_template("calendar.html")

@login_required
@app.route('/pay')
def payment():
    return render_template("pay.html")

@login_required
@app.route('/team_stats', methods=['GET', 'POST'])
def team_stats():
   if request.method == 'POST':
       username = request.form['username']
       password_input = request.form['password']
       teamname = request.form['teamname']

       database_password = get_password(username)
       unciphered_text = "1"
       try:
           unciphered_text = decipher_text(database_password)
           if unciphered_text == password_input:  # successfully logged in
               conn = sqlite3.connect(database_name)
               c = conn.cursor()

               return render_template("team_stats.html", logged_in = True, competitors = get_competitors_of_team(c,conn,teamname))
           else:
               error = 'Invalid Credentials. Please try again.' 
       except cryptography.fernet.InvalidToken:
           flash('Not the right password for that username')
           return render_template('team_stats.html', error='Not the right password for that username',logged_in = True)
   return render_template("team_stats.html",not_logged_in = True)

@app.route('/forgotten_password')
def render_underconstruction():
    return render_template('under_development.html')

@app.route('/')
@app.route('/coach_teams', methods=['GET', 'POST'])
def coach_teams():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        database_password = get_password(username)
        teams = None
        unciphered_text = "1"
        try:
            unciphered_text = decipher_text(database_password)
            if unciphered_text == password_input:  # successfully logged in
                conn = sqlite3.connect(database_name)
                c = conn.cursor()
                teams = get_teams_of_coach(c,conn,username)
                return render_template("coach_teams.html", logged_in = True, teams = teams)
            else:
                error = 'Invalid Credentials. Please try again.' 
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template('coach_teams.html', error='Not the right password for that username',logged_in = True)
    return render_template("coach_teams.html",not_logged_in = True)


@login_required
@app.route('/change_password', methods=['GET', 'POST'])
def authentication():
    if request.method == 'POST':
        conn = sqlite3.connect(database_name)
        c = conn.cursor()

        name = request.form['username']
        oldpassword = request.form['oldpassword']
        password = request.form['password']

        database_password = decipher_text(get_password(name))

        if str(database_password) == str(oldpassword):
            print "Correct login credentials"
            change_password(name,password)
            print "Successfully changed the password"
        else: 
            print "WRONG PSSWD"
    return render_template("change_password.html")


@login_required
@app.route('/competitors')
def competitor():
    conn = sqlite3.connect(database_name)
    c = conn.cursor()
    competitors = get_all_competitors(c,conn)
    print competitors
    return render_template('competitor.html',competitors = competitors)


@app.route('/competitors_information', methods=['GET', 'POST'])
def insert_info(name = "Guest", email = "none"):

    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        height = request.form['height']
        age = request.form['age']
        weight = request.form['weight']
        teamname = request.form['teamname']

        conn = sqlite3.connect(database_name)
        c = conn.cursor()

        database_password = get_password(username)
        unciphered_text = None
        try:
            unciphered_text = decipher_text(database_password)
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
        if unciphered_text == password_input:
            # that's the right password
            print "Right credentials"
            competitor = new_competitor(c,conn,teamname,username,age,height,weight)
            if competitor:
                success = "Successfully registered this competitor!"
            else:
                success = "Successfully updated this competitor!"

        else:
            error = 'Invalid Credentials. Please try again.'
    
    return render_template('competitors_information.html', error = error, success = success)


@app.route('/teams')
def test_route():
    conn = sqlite3.connect(database_name)
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
    return render_template('teams.html', teams=teams,names=names,countries = countries,length_teams = len(teams))


@login_required
@app.route('/register_team', methods=['GET', 'POST'])
def register_team():
    form = TeamsForm(request.form)
    print form.errors
    if request.method == 'POST':
        conn = sqlite3.connect(database_name)
        c = conn.cursor()

        name = request.form['name']
        country = request.form['country']
        coach = request.form['coach']

        if form.validate() and is_coach(coach):
            c.execute("INSERT INTO {} VALUES(?, ?)".format("Teams(team_name,country)"), (name,country))
            c.execute("INSERT INTO {} VALUES(?, ?)".format("TeamsCoaches(team_name,coach_name)"), (name,coach))
            conn.commit()
            print "HERE"
            return render_template('succesfully_registered_team.html',teamname = name,coach = coach, country = country)
        elif is_coach(coach) == False:
            flash('Error: Not a valid coach.')
        else:
            flash('Error: All the form fields are required.')
    return render_template('register_team.html', form=form)
  

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        database_password = get_password(username)
        print database_password
        unciphered_text = "123"
        try:
            unciphered_text = decipher_text(database_password)
            print database_password, unciphered_text
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template('login.html', error='Not the right password for that username')
        if unciphered_text == password_input:
            user = User()
            login_user(user)
            conn = sqlite3.connect(database_name)
            c = conn.cursor()
            # return coach_or_competitor(username)
            role = get_role(c,conn,username)
            email = get_email_from_username(c,conn,username)
            return signed_in(role,username, email)
        else:
            error = 'Invalid Credentials. Please try again.' 
    return render_template('login.html', error=error)
 


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    print form.errors

    if request.method == 'POST':
        conn = sqlite3.connect(database_name)
        c = conn.cursor()

        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['options'] # coach - 1, competitor - 2

        ciphered_password = cipher_text(password)

        if form.validate() and is_valid_email(email) == True:
            c.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format("Users(name,email,password,role)"), (name,email,ciphered_password,role))
            conn.commit()
            
            return signed_in(role,name,email)
        elif is_valid_email == False:
            flash('Error: That is not a valid email address')
        else:
            flash('Error: All the form fields are required. Mail must be at least 6 chars and the password - at least 3')
    return render_template('register.html', form=form)




""" 
------------------------------------------------------------------------
                            ERROR HANDLING SECTION
------------------------------------------------------------------------
"""
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

""" 
------------------------------------------------------------------------
                            DATABASE TABLES SECTION
------------------------------------------------------------------------
"""
def drop_all_tables():
    """ drops all database tables"""
    conn = sqlite3.connect(database_name)
    c = conn.cursor()
    c.execute("DROP TABLE Users")
    c.execute("DROP TABLE Teams")
    c.execute("DROP TABLE TeamsCoaches")
    c.execute("DROP TABLE Competitors")

def create_all_tables():
    """ creates all database tables"""
    conn = sqlite3.connect(database_name)
    c = conn.cursor()
    create_table_for_teams(c,conn)
    create_table_for_users(c,conn)
    create_teams_coach_table(c,conn)
    create_competitors_table(c,conn)
    create_events_table(c,conn)

def create_table_for_users(c,conn):
    """creates the table for the teams
    
    Args:
        c: the cursor
        conn: the connection to the db
        
    """
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
        c: the cursor
        conn: the connection to the db
        
    """
    c.execute("""
        CREATE TABLE Teams(
        id INTEGER PRIMARY KEY,
        team_name text,
        country text)""")
    conn.commit()


def create_teams_coach_table(c,conn):
    """creates the connection table for teams and coaches

    Args:
        c: the cursor
        conn: the connection to the db
        
    """

    c.execute("""
        CREATE TABLE TeamsCoaches(
        id INTEGER PRIMARY KEY,
        team_name text,
        coach_name text)""")
    conn.commit()


def create_competitors_table(c,conn):
    """creates the competitors table =

    Args:
        c: the cursor
        conn: the connection to the db
        
    """

    c.execute("""
        CREATE TABLE Competitors(
        id INTEGER PRIMARY KEY,
        teamname text,
        competitorname text,
        age text,
        height text,
        weight text)""")
    conn.commit()

def create_events_table(c,conn):
    """creates the table for the events

    Args:
        c: the cursor
        conn: the connection to the db
        
    """

    c.execute("""
        CREATE TABLE Events(
        id INTEGER PRIMARY KEY,
        eventname text,
        eventdescription text,
        hostname text,
        eventdate NUMERIC,
        location text)""")
    conn.commit()
    print "Created evenets table.."


""" 
------------------------------------------------------------------------
                        DATABASE QUERIES SECTION
------------------------------------------------------------------------
"""

def get_all_competitors(c,conn):
    """  gets a list of all the competitors

    Args:
        c: the cursor
        conn: the connection to the db
    
    Returns:
        tuple with the names of the competitors

    """
    c.execute("Select competitorname from Competitors")
    competitors = []

    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            competitors.append(res[0])
    return competitors

def get_all_events(c,conn):
    """  gets a list of all the events

    Args:
        c: the cursor
        conn: the connection to the db
    
    Returns:
        tuple with the names of the events

    """
    c.execute("Select eventname from Events")
    events = []

    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            events.append(res[0])
    return events

def new_competitor(c,conn,teamname,competitorname,age,height,weight):
    """ Creates a new competitor and adds him to the database. 
        If competitor already exists - updates some values.

    Args:
        c: the cursor
        conn: the connection to the db
        teamname: the name that the competitor is registered at
        competitorname: the name of the competitor
        age: the age of the competitor
        height: the height of the competito
        weight: the weight of the competito
    
    Returns:
        True if created a competitor, False if updated a competitor

    """
    c.execute("Select id from Competitors where teamname = '{}' and competitorname = '{}'".format(teamname,competitorname))
    res = c.fetchone()
    if res is None : 
        c.execute("INSERT INTO {} VALUES(?, ?, ?, ?, ?)".format("Competitors(teamname,competitorname,age,height,weight)"), (teamname,competitorname,age,height,weight))
        conn.commit()
        return True
    else: # Already in database
        c.execute("""update Competitors set age = '{}',height = '{}',
            weight = '{}' where teamname = '{}' and competitorname = '{}'"""
            .format(age,height,weight,teamname,competitorname))
        conn.commit() 
        return False

def get_role(c,conn,username):
    """gets what is the role of the user with username
    
    Args:
        c: the cursor
        conn: the connection to the db
        username: the username that should be checked to see if it's a competitor or coach

    Returns:
        the role of the user

    """
    c.execute("Select role from Users where name = '{}'".format(username))
    res = c.fetchone()
    print "role is " + str(res)
    return res 


def get_email_from_username(c,conn,username):
    """gets what is the email 
    
    Args:
        c: the cursor
        conn: the connection to the db
        username: the username that should be used
    
    Returns:
        the email of the user    

    """
    c.execute("Select email from Users where name = '{}'".format(username))
    res = c.fetchone()
    print "mail is " + str(res)
    return res 

def get_password(username):
    """gets the password of a user

    Args:
        username: the username for whose password we are looking
    
    Returns:
        the password stored in the database
        
    """
    conn = sqlite3.connect(database_name)
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
    conn = sqlite3.connect(database_name)
    c = conn.cursor()
    c.execute("Select role from Users where name = '{}'".format(username))
    res = str(c.fetchone())
    res = clean_up_database_str(res)
    if res == "1": return True
    return False

def get_teams_of_coach(c,conn,coach):
    """gets all the teams a coach has

    Args:
        c: the cursor
        conn: the connection to the db
        coach: the name of the coach
    
    Returns:
        a list of all the teams a coach has

    """
    c.execute("Select team_name from TeamsCoaches where coach_name = '{}'".format(coach))
    teams = []
    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            teams.append(res[0])
    return teams

def get_competitors_of_team(c,conn,teamname):
    """gets all the teams a coach has

    Args:
        c: the cursor
        conn: the connection to the db
        teamname: the name of the team
    
    Returns:
        a list of all the competitors a team has

    """
    c.execute("Select competitorname from Competitors where teamname = '{}'".format(teamname))
    competitors = []
    while True:
        res = c.fetchone()
        if res is None:
            break
        else:
            competitors.append(res[0])
            print res[0]
    return competitors
def change_password(username, newpassword):
    """changes password in the database of a selected user

    Args:
        username: the username that should be checked
        
    """ 
    conn = sqlite3.connect(database_name)
    c = conn.cursor() 
    password = cipher_text(newpassword)
    c.execute("update Users set password= '{}' where name = '{}'".format(password,username))
    conn.commit()
 


def matching_username_and_password(username,password):
    """chekcs if the given password matches the username

    Args:
        username: the string that should be used as username
        password: the string that should be used as password

    Returns:
        True if that's the correct password, False otherwise

    """

    current_psswd = get_password(username)
    password = cipher_text(password)

    if current_psswd == password: # passwords match
        return True
    return False


""" 
------------------------------------------------------------------------
                    HELPING FUNCTIONS SECTION
------------------------------------------------------------------------
"""
def clean_up_database_str(str):
    """Removes unneded chars from the string, retrieved from the database

    Args:
        str: the string that should be parsed

    Returns:
        The fixed string

    """
    return str[3:-3] 

def is_valid_email(email):
    """checks email against regex

    Args:
        email: the email that should be checked

    Returns:
        True if it's a valid email, False otherwise

    """
    regex = '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$'
    is_valid_email = re.match(regex, email)
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
    f = get_fernet_key()
    return f.encrypt(string_to_bytes(text_to_cipher))   

def decipher_text(text_to_decipher):
    """decipers a string

    Args:
        text_to_decipher: the text that should be decipered

    Returns:
        the unciphered text

    """
    f = get_fernet_key()
    return f.decrypt(string_to_bytes(text_to_decipher))

def get_fernet_key():
    """gets an instance of a class that handles salting and encryption of passwords

    Returns:
        an instance of the Fernet class

    """

    salt = bytes(10)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    password = b"password"
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

def string_to_bytes(text):
    """converts a string to bytes

    Args:
        text: the text that should be converted

    Returns:
        the converted text

    """
    return str.encode(str(text))

def coach_or_competitor(username):
    if is_coach(username) == True:
        print "This user is a coach"
        return render_template("signed_in.html",loggedin = True)
    else:
        print "This user is a competitor"
        return render_template("competitor.html", loggedin = True) 

def signed_in(role,name,email):
    if role == str(2):
        redirect_code = 302
        return redirect("http://127.0.0.1:5000/competitors_information")
        # return render_template("competitors_information.html", name = name, email = email,verify = True)
    else:
        return render_template("signed_in.html", name = name, email = email,verify = True,coach = True)