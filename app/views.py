""" sportstat """

import sqlite3
import re
import base64
import cryptography
from flask import flash, redirect, render_template, request
from wtforms import Form, TextField, validators
from flask_login import login_required
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app import app

# logging.basicConfig(filename='app_log.log', level=logging.DEBUG,format='%(asctime)s:%(message)s')


DB_NAME = "test.db"

class RegistrationForm(Form):
    """ form for registration of user """
    name = TextField('Name:', validators=[validators.required()])
    email = TextField(
        'Email:',
        validators=[
            validators.required(),
            validators.Length(
                min=6,
                max=35)])
    password = TextField(
        'Password:',
        validators=[
            validators.required(),
            validators.Length(
                min=3,
                max=35)])


class TeamsForm(Form):
    """ form for registration of team """
    name = TextField('Name:', validators=[validators.required()])
    coach = TextField('Coach:', validators=[validators.required()])
    country = TextField('Country:', validators=[validators.required()])


class CompetitorsForm(Form):
    """ form for registration of team """
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required()])
    age = TextField(
        'Age:',
        validators=[
            validators.required(),
            validators.Length(
                min=1,
                max=3)])
    weight = TextField(
        'Weight:',
        validators=[
            validators.required(),
            validators.Length(
                min=2,
                max=4)])
    height = TextField(
        'Height:',
        validators=[
            validators.required(),
            validators.Length(
                min=2,
                max=4)])
    teamname = TextField('Teamname:', validators=[validators.required()])


@app.route('/')
@app.route('/about')
def index():
    """ page for basic info """
    return render_template("index.html")


@app.route('/stream')
def stream():
    """ page for streaming """
    return render_template("stream.html")


@login_required
@app.route('/new_event', methods=['GET', 'POST'])
def create_event():
    """page for creating event"""
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        eventname = request.form['name']
        eventdescription = request.form['eventdescription']
        location = request.form['location']

        hostname = username

        database_password = get_password(username)
        unciphered_text = None
        try:
            unciphered_text = decipher_text(database_password)
            if unciphered_text == password_input:  # successfully logged in
                create_new_event(
                    eventname,
                    eventdescription,
                    hostname,
                    location)
                return render_template("new_event.html", logged_in=True)
            else:
                pass
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template(
                'new_event.html',
                error='Not the right password for that username',
                not_logged_in=True)
    return render_template("new_event.html", not_logged_in=True)


@app.route('/calendar')
def calendar():
    """page for all events"""
    events = get_all_events(sqlite3.connect(DB_NAME).cursor())
    return render_template("calendar.html", events=events)


@login_required
@app.route('/pay')
def payment():
    """page for payment"""
    return render_template("pay.html")


@login_required
@app.route('/team_stats', methods=['GET', 'POST'])
def team_stats():
    """ page for stats of team """
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        teamname = request.form['teamname']

        database_password = get_password(username)
        unciphered_text = None
        try:
            unciphered_text = decipher_text(database_password)
            if unciphered_text == password_input:  # successfully logged in
                conn = sqlite3.connect(DB_NAME)

                return render_template(
                    "team_stats.html",
                    logged_in=True,
                    competitors=get_competitors_of_team(
                        conn.cursor(),
                        teamname))
            else:
                pass
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template(
                'team_stats.html',
                error='Not the right password for that username',
                logged_in=True)
    return render_template("team_stats.html", not_logged_in=True)


@app.route('/forgotten_password')
def render_underconstruction():
    """render html for when page is under construction"""
    return render_template('under_development.html')


@app.route('/')
@app.route('/coach_teams', methods=['GET', 'POST'])
def coach_teams():
    """renders all teams of certain coach"""
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        database_password = get_password(username)
        teams = None
        unciphered_text = "1"
        try:
            unciphered_text = decipher_text(database_password)
            if unciphered_text == password_input:  # successfully logged in
                conn = sqlite3.connect(DB_NAME)
                teams = get_teams_of_coach(conn.cursor(), username)
                return render_template(
                    "coach_teams.html", logged_in=True, teams=teams)
            else:
                pass
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
            return render_template(
                'coach_teams.html',
                error='Not the right password for that username',
                logged_in=True)
    return render_template("coach_teams.html", not_logged_in=True)


@login_required
@app.route('/change_password', methods=['GET', 'POST'])
def authentication():
    """change psswd"""
    if request.method == 'POST':
        name = request.form['username']
        oldpassword = request.form['oldpassword']
        password = request.form['password']

        database_password = decipher_text(get_password(name))

        if str(database_password) == str(oldpassword):
            print "Correct login credentials"
            change_password(name, password)
        else:
            print "Wrong login credentials"
    return render_template("change_password.html")


@login_required
@app.route('/competitors')
def competitor():
    """get all competitors"""
    competitors = get_all_competitors(sqlite3.connect(DB_NAME).conn.cursor())
    return render_template('competitor.html', competitors=competitors)


@app.route('/competitors_information', methods=['GET', 'POST'])
def insert_info():
    """insert competitors information"""
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        height = request.form['height']
        age = request.form['age']
        weight = request.form['weight']
        teamname = request.form['teamname']


        database_password = get_password(username)
        unciphered_text = None
        try:
            unciphered_text = decipher_text(database_password)
        except cryptography.fernet.InvalidToken:
            flash('Not the right password for that username')
        if unciphered_text == password_input:
            # that's the right password
            print "Right credentials"
            new_competitor(teamname, username, age, height, weight)
        else:
            error = 'Invalid Credentials. Please try again.'

    return render_template(
        'competitors_information.html',
        error=error,
        success=success)


@app.route('/teams')
def all_teams():
    """ print all teams"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("select team_name from Teams")

    teams = []
    names = []
    countries = []

    while True:
        res = cursor.fetchone()
        if res is None:
            break
        else:
            teams.append(res)
            names.append(res[0])
    return render_template(
        'teams.html',
        teams=teams,
        names=names,
        countries=countries,
        length_teams=len(teams))


@login_required
@app.route('/register_team', methods=['GET', 'POST'])
def register_team():
    """ create a team"""
    form = TeamsForm(request.form)
    print form.errors
    if request.method == 'POST':
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        name = request.form['name']
        country = request.form['country']
        coach = request.form['coach']

        if form.validate() and is_coach(coach):
            cursor.execute("INSERT INTO {} VALUES(?, ?)".format(
                "Teams(team_name,country)"), (name, country))
            cursor.execute("INSERT INTO {} VALUES(?, ?)".format(
                "TeamsCoaches(team_name,coach_name)"), (name, coach))
            conn.commit()
            return render_template(
                'succesfully_registered_team.html',
                teamname=name,
                coach=coach,
                country=country)
        elif is_coach(coach) is not True:
            flash('Error: Not a valid coach.')
        else:
            flash('Error: All the form fields are required.')
    return render_template('register_team.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """login"""
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
            return render_template(
                'login.html',
                error='Not the right password for that username')
        if unciphered_text == password_input:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            role = get_role(cursor, username)
            email = get_email_from_username(cursor, username)
            return signed_in(role, username, email)
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route("/register", methods=['GET', 'POST'])
def register():
    """register"""
    form = RegistrationForm(request.form)
    print form.errors

    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['options']  # coach - 1, competitor - 2

        ciphered_password = cipher_text(password)

        if form.validate() and is_valid_email(email):
            conn = sqlite3.connect(DB_NAME)
            conn.cursor().execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format(
                "Users(name,email,password,role)"), (name, email, ciphered_password, role))
            conn.commit()

            return signed_in(role, name, email)
        elif is_valid_email is not True:
            flash('Error: That is not a valid email address')
        else:
            error_mssg = 'Error: All the form fields are required.'
            flash(error_mssg)
    return render_template('register.html', form=form)


@app.errorhandler(404)
def page_not_found(error_to_handle):
    """404"""
    print error_to_handle
    return render_template('404.html'), 404


def drop_all_tables():
    """ drops all database tables"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE Users")
    cursor.execute("DROP TABLE Teams")
    cursor.execute("DROP TABLE TeamsCoaches")
    cursor.execute("DROP TABLE Competitors")
    cursor.execute("DROP TABLE Events")


def create_all_tables():
    """ creates all database tables"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    create_table_for_teams(cursor, conn)
    create_table_for_users(cursor, conn)
    create_teams_coach_table(cursor, conn)
    create_competitors_table(cursor, conn)
    create_events_table(cursor, conn)


def create_table_for_users(cursor, conn):
    """creates the table for the teams

    Args:
        cursor: the cursor
        conn: the connection to the db

    """
    cursor.execute(""" CREATE TABLE Users(
        id INTEGER PRIMARY KEY,
        name text,
        email text,
        password text,
        role text
    )""")
    conn.commit()


def create_table_for_teams(cursor, conn):
    """creates the table for the teams

    Args:
        cursor: the cursor
        conn: the connection to the db

    """
    cursor.execute("""
        CREATE TABLE Teams(
        id INTEGER PRIMARY KEY,
        team_name text,
        country text)""")
    conn.commit()


def create_teams_coach_table(cursor, conn):
    """creates the connection table for teams and coaches

    Args:
        cursor: the cursor
        conn: the connection to the db

    """

    cursor.execute("""
        CREATE TABLE TeamsCoaches(
        id INTEGER PRIMARY KEY,
        team_name text,
        coach_name text)""")
    conn.commit()


def create_competitors_table(cursor, conn):
    """creates the competitors table =

    Args:
        cursor: the cursor
        conn: the connection to the db

    """

    cursor.execute("""
        CREATE TABLE Competitors(
        id INTEGER PRIMARY KEY,
        teamname text,
        competitorname text,
        age text,
        height text,
        weight text)""")
    conn.commit()


def create_events_table(cursor, conn):
    """creates the table for the events

    Args:
        cursor: the cursor
        conn: the connection to the db

    """

    cursor.execute("""
        CREATE TABLE Events(
        id INTEGER PRIMARY KEY,
        eventname text,
        eventdescription text,
        hostname text,
        location text)""")
    conn.commit()
    print "Created evenets table.."



def create_new_event(name, descr, host, location):
    """  gets a list of all the competitors

    Args:
        name: event name
        descr: description of the event
        host: nme of the event host(coach)
        location: the address of the event

    Returns:
        tuple with the names of the events

    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO {} VALUES(?, ?, ?, ?)".format(
        "Events(eventname,eventdescription,hostname,location)"), (name, descr, host, location))

    conn.commit()
    print "successfully created event"


def get_all_competitors(cursor):
    """  gets a list of all the competitors

    Args:
        cursor: the cursor

    Returns:
        tuple with the names of the competitors

    """
    cursor.execute("Select competitorname from Competitors")
    competitors = []

    while True:
        res = cursor.fetchone()
        if res is None:
            break
        else:
            competitors.append(res[0])
    return competitors


def get_all_events(cursor):
    """  gets a list of all the events

    Args:
        cursor: the cursor

    Returns:
        tuple with the names of the events

    """
    cursor.execute("Select eventname,eventdescription,hostname,location from Events")
    events = []

    while True:
        res = cursor.fetchone()
        if res is None:
            break
        else:
            string_to_print = "Event name: " + res[0] + "\n" + "\nEvent description: " + \
                res[1] + " \n" + "\nHosted by:  " + res[2] + "\n" + "\n Location: " + res[3] + "\n"
            events.append(string_to_print)
    return events


def new_competitor(teamname, competitorname, age, height, weight):
    """ Creates a new competitor and adds him to the database.
        If competitor already exists - updates some values.

    Args:
        teamname: the name that the competitor is registered at
        competitorname: the name of the competitor
        age: the age of the competitor
        height: the height of the competito
        weight: the weight of the competito

    Returns:
        True if created a competitor, False if updated a competitor

    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "Select id from Competitors where teamname = '{}' and competitorname = '{}'".format(
            teamname,
            competitorname))
    res = cursor.fetchone()
    if res is None:
        cursor.execute("INSERT INTO {} VALUES(?, ?, ?, ?, ?)".format(
            "Competitors(teamname,competitorname,age,height,weight)"),
                       (teamname, competitorname, age, height, weight))
        conn.commit()
        return True
    else:  # Already in database
        cursor.execute("""update Competitors set age = '{}',height = '{}',
            weight = '{}' where teamname = '{}' and competitorname = '{}'"""
                       .format(age, height, weight, teamname, competitorname))
        conn.commit()
        return False


def get_role(cursor, username):
    """gets what is the role of the user with username

    Args:
        cursor: the cursor
        username: the username that should be checked to see if it's a competitor or coach

    Returns:
        the role of the user

    """
    cursor.execute("Select role from Users where name = '{}'".format(username))
    res = cursor.fetchone()
    print "role is " + str(res)
    return res


def get_email_from_username(cursor, username):
    """gets what is the email

    Args:
        cursor: the cursor
        conn: the connection to the db
        username: the username that should be used

    Returns:
        the email of the user

    """
    cursor.execute("Select email from Users where name = '{}'".format(username))
    res = cursor.fetchone()
    print "mail is " + str(res)
    return res


def get_password(username):
    """gets the password of a user

    Args:
        username: the username for whose password we are looking

    Returns:
        the password stored in the database

    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("Select password from Users where name = '{}'".format(username))
    res = str(cursor.fetchone())
    return clean_up_database_str(res)


def is_coach(username):
    """checks if the given username is a coach

    Args:
        username: the username that should be checked

    Returns:
        True if is a coach, False otherwise

    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("Select role from Users where name = '{}'".format(username))
    res = str(cursor.fetchone())
    res = clean_up_database_str(res)
    if res == "1":
        return True
    return False


def get_teams_of_coach(cursor, coach):
    """gets all the teams a coach has

    Args:
        cursor: the cursor
        coach: the name of the coach

    Returns:
        a list of all the teams a coach has

    """
    cursor.execute(
        "Select team_name from TeamsCoaches where coach_name = '{}'".format(coach))
    teams = []
    while True:
        res = cursor.fetchone()
        if res is None:
            break
        else:
            # append_this = res[0] + ",coached by " + coach
            teams.append(res[0])
    return teams


def get_competitors_of_team(cursor, teamname):
    """gets all the teams a coach has

    Args:
        cursor: the cursor
        conn: the connection to the db
        teamname: the name of the team

    Returns:
        a list of all the competitors a team has

    """
    cursor.execute(
        "Select competitorname from Competitors where teamname = '{}'".format(teamname))
    competitors = []
    while True:
        res = cursor.fetchone()
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
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    password = cipher_text(newpassword)
    cursor.execute(
        "update Users set password= '{}' where name = '{}'".format(
            password, username))
    conn.commit()
    print "Successfully changed the password"


def matching_username_and_password(username, password):
    """chekcs if the given password matches the username

    Args:
        username: the string that should be used as username
        password: the string that should be used as password

    Returns:
        True if that's the correct password, False otherwise

    """

    current_psswd = get_password(username)
    password = cipher_text(password)

    if current_psswd == password:  # passwords match
        return True
    return False


def clean_up_database_str(string_to_transform):
    """Removes unneded chars from the string, retrieved from the database

    Args:
        string_to_transform: the string that should be parsed

    Returns:
        The fixed string

    """
    return string_to_transform[3:-3]


def is_valid_email(email):
    """checks email against regex

    Args:
        email: the email that should be checked

    Returns:
        True if it's a valid email, False otherwise

    """
    regex = r'^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$'
    if re.match(regex, email) is None:
        return False
    return True


def cipher_text(text_to_cipher):
    """cipers a string

    Args:
        text_to_cipher: the text that should be cipered

    Returns:
        the ciphered text

    """
    ferneted = get_fernet_key()
    return ferneted.encrypt(string_to_bytes(text_to_cipher))


def decipher_text(text_to_decipher):
    """decipers a string

    Args:
        text_to_decipher: the text that should be decipered

    Returns:
        the unciphered text

    """
    ferneted = get_fernet_key()
    return ferneted.decrypt(string_to_bytes(text_to_decipher))


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
    """converts a string to bytes

    Args:
        username: the user whose should be checked

    Returns:
        renders the competiotr template if user is comeptitor or the coach one if coach

    """
    if is_coach(username):
        print "This user is a coach"
        return render_template("signed_in.html", loggedin=True)
    else:
        print "This user is a competitor"
        return render_template("competitor.html", loggedin=True)


def clean_database():
    """creates db from scratch"""
    drop_all_tables()
    create_all_tables()


def signed_in(role, name, email):
    """signs in user

    Args:
        role: are you coach or competitor
        name: the username for signing
        email: the email for signing

    Returns:
        True if it's a valid email, False otherwise

    """
    if role == str(2):
        return redirect("http://127.0.0.1:5000/competitors_information")
    else:
        return render_template(
            "signed_in.html",
            name=name,
            email=email,
            verify=True,
            coach=True)
