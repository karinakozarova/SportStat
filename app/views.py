from flask import render_template

from app import app


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


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