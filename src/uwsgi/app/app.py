import uuid
from datetime import timedelta

from flask import Flask, render_template, request, make_response, session
import mysql.connector as mariadb
import os
import time
from bcrypt import hashpw, checkpw, gensalt
from cachelib import SimpleCache
import app.init as dbinit

app = Flask(__name__, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY")
db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
sql = db.cursor(buffered=True)
dbinit.init()
sql.execute("USE od")
salt = gensalt(12)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
cache = SimpleCache()


@app.route("/", methods=["GET"])
def index():
    sql.execute('SELECT * FROM notes')
    data = sql.fetchall()
    print(data)
    return render_template("home.html")


@app.route("/login", methods=["POST"])
def login_user():
    login = request.form.get("login")
    if cache.get(f'{login}Block'):
        return make_response("Exceeded allowed number of login attempts. Please try again in 10 minutes.")
    print("Blocked? " + str(cache.get(f'{login}Blocked')))
    print("Attempts " + str(cache.get(f'{login}Attempts')))
    password = request.form.get("password")
    if None in [login, password]:
        return make_response("Not every field was filled!", 400)
    if login_check(login, password) is False:
        att = cache.get(f'{login}Attempts')
        if att is None:
            cache.set(f'{login}Attempts', 1, timeout=600)
        else:
            cache.set(f'{login}Attempts', att + 1, timeout=600)
            if att + 1 > 5:
                cache.set(f'{login}Block', True, timeout=600)
        return make_response("Invalid credentials", 400)
    cache.set(f'{login}Attempts', 0)
    session_id = uuid.uuid4().hex
    sql.execute("INSERT INTO session (sid, login) VALUES (%(sid)s, %(login)s)", {'sid': session_id, 'login': login})
    db.commit()
    response = make_response("", 301)
    session["session-id"] = session_id
    session['identity'] = login
    session.permanent = True
    response.headers["Location"] = "/"
    return response


def login_check(login, password):
    sql.execute("SELECT password FROM users WHERE login = %(login)s", {'login': login})
    db_password, = sql.fetchone() or (None,)
    password = password.encode()
    if not db_password:
        print(f'User with {login} does not exist')
        return False
    db_password = db_password.encode()
    return checkpw(password, db_password)


@app.route("/register", methods=["POST"])
def register():
    login = request.form.get("login")
    password = request.form.get("password")
    repeat_password = request.form.get("repeat-password")
    email = request.form.get("email")

    if None in [login, password, repeat_password, email]:
        return make_response("Not every field was filled!", 400)
    if password != repeat_password:
        return make_response("Passwords do not match!", 400)
    if not check_login_availability(login):
        return make_response("Login taken", 400)

    save_user(login, password, email)

    return make_response("All good", 200)


def save_user(login, password, email):
    try:
        password = password.encode()
        hashed_pass = hashpw(password, salt)
        sql.execute("INSERT INTO users (login, email, password) VALUES (%(login)s, %(email)s, %(password)s);",
                    {'login': login, 'email': email, 'password': hashed_pass})
        db.commit()
        return True
    except Exception:
        return False


def check_login_availability(login):
    sql.execute("SELECT EXISTS(SELECT 1 FROM users WHERE login = %(login)s LIMIT 1)", {'login': login})
    db_login, = sql.fetchone() or (None,)
    print(db_login)
    if not db_login:
        return True
    else:
        return False


@app.route("/logout")
def logout():
    if session.get('identity') is not None:
        user = session['identity']
        sql.execute("DELETE FROM session WHERE login = %(login)s", {'login': user})
        response = make_response("", 301)
        session.clear()
        response.headers["Location"] = "/"
        return response
    else:
        return make_response("You cannot logout if you're not logged in!", 400)
