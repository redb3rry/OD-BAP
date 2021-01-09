import uuid
from datetime import timedelta

from flask import Flask, render_template, request, make_response, session, send_file, logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import mysql.connector as mariadb
import os
from bcrypt import hashpw, checkpw, gensalt
from cachelib import RedisCache
import app.init as dbinit
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY")
db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
sql = db.cursor(buffered=True)
dbinit.init()
sql.execute("USE od")
salt = gensalt(12)
key = get_random_bytes(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
cache = RedisCache(host='redis-cache', port=6379)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'txt'}
app.config['UPLOAD_FOLDER'] = 'app/files/'
csrf = CSRFProtect(app)


@app.route("/", methods=["GET"])
def index():
    return render_template("home.html")


@app.before_first_request
def prepare():
    save_user("user", "password", "user@email.com")
    save_user("admin", "admin", "admin@email.com")
    save_user("ceo", "honeypot", "ceo@email.com")
    add_new_ip_to_user("172.28.0.1", "user")
    add_new_ip_to_user("166.36.52.57", "admin")


@app.route("/login", methods=["POST"])
def login_user():
    login = request.form.get("login")
    if cache.get(f'{login}Attempts') is not None and cache.get(f'{login}Attempts') > 5:
        return make_response("Exceeded allowed number of login attempts. Please try again in 10 minutes.")
    password = request.form.get("password")
    if None in [login, password]:
        return make_response("Not every field was filled!", 400)
    if login_check(login, password) is False:
        att = cache.get(f'{login}Attempts')
        if att is None:
            cache.set(f'{login}Attempts', 1, timeout=600)
        else:
            cache.set(f'{login}Attempts', att + 1, timeout=600)
        return make_response("Invalid credentials", 400)
    cache.set(f'{login}Attempts', 0)
    session_id = uuid.uuid4().hex
    sql.execute("INSERT INTO session (sid, login) VALUES (%(sid)s, %(login)s)", {'sid': session_id, 'login': login})
    db.commit()
    ip = request.access_route[0]
    if add_new_ip_to_user(ip, login):
        sql.execute("SELECT email FROM users WHERE login = %(login)s", {'login': login})
        email, = sql.fetchone() or (None,)
        response = make_response(
            f"Logged in from new ip. Sending email to: {email} \n A new machine with this ip address: {ip}, has accessed your account. If you do not recognize this login please change your password immediately.")
        session["session-id"] = session_id
        session['identity'] = login
        session.permanent = True
        return response
    response = make_response("Logged in", 301)
    session["session-id"] = session_id
    session['identity'] = login
    session.permanent = True
    response.headers["Location"] = "/notelist"
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

    ip = request.access_route[0]
    save_user(login, password, email)
    add_new_ip_to_user(ip, login)
    response = make_response("Registered", 301)
    response.headers["Location"] = "/"
    return response


def add_new_ip_to_user(ip, login):
    sql.execute("SELECT ip FROM ips WHERE login=%(login)s", {'login': login})
    allowed_ips = sql.fetchall()
    ip_tuple = ip,
    if allowed_ips is None or ip_tuple not in allowed_ips:
        sql.execute("INSERT INTO ips (login, ip) VALUES (%(login)s, %(ip)s)", {'login': login, 'ip': ip})
        db.commit()
        return True
    return False


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
    if not db_login:
        return True
    else:
        return False


@app.route("/logout")
def logout():
    if session.get('identity') is not None:
        user = session['identity']
        sql.execute("DELETE FROM session WHERE login = %(login)s", {'login': user})
        db.commit()
        response = make_response("Logged out", 301)
        session.clear()
        response.headers["Location"] = "/"
        return response
    else:
        return make_response("You cannot logout if you're not logged in!", 400)


@app.route("/addnote", methods=["GET", "POST"])
def addnote():
    if session.get('identity') is not None:
        if request.method == "POST":
            user = session['identity']
            note_text = request.form.get("note-text")
            note_name = request.form.get("note-name")
            if len(note_name) > 50:
                return make_response("Note name is too long!", 400)
            privacy = request.form.get("privacyOptions")
            if privacy == "secure":
                note_text, nonce = encrypt(note_text.encode('utf-8'))
                note_text = b64encode(note_text).decode('utf-8')
                nonce = b64encode(nonce).decode('utf-8')
                password = request.form.get("note-password").encode()
                if password is None:
                    return make_response("No password supplied for secure note", 400)
                password = hashpw(password, salt)
            else:
                password = None
                nonce = None
            sql.execute("INSERT INTO notes(login, notename, content, privacy, password, nonce) "
                        "VALUES (%(user)s,%(note_name)s, %(note_text)s, %(privacy)s, %(password)s, %(nonce)s)",
                        {'user': user, 'note_name': note_name, 'note_text': note_text, 'privacy': privacy,
                         'password': password, 'nonce': nonce})
            response = make_response("Note added", 301)
            response.headers["Location"] = "/notelist"
            return response

        else:
            return render_template("addnote.html")
    else:
        return make_response("You are not logged in!", 400)


def encrypt(data):
    cipher = AES.new(key, AES.MODE_CTR)
    encrypted = cipher.encrypt(data)
    nonce = cipher.nonce
    return encrypted, nonce


def decrypt(data, nonce):
    nonce = b64decode(nonce)
    data = b64decode(data)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(data).decode('utf-8')
    return decrypted


@app.route("/notelist", methods=["GET"])
def notelist():
    if session.get('identity') is not None:
        login = session.get('identity')
        sql.execute(
            "SELECT notes.login, notes.notename, notes.privacy, notes.noteid FROM notes WHERE notes.login = %(login)s",
            {'login': login})
        data = sql.fetchall()
        notes = data
        num_of_notes = len(notes)
        names = []
        privacies = []
        note_ids = []
        for i in range(num_of_notes):
            note = notes[i]
            names.append(note[1])
            privacies.append(note[2])
            note_ids.append(note[3])
        return render_template("notelist.html", num_of_notes=num_of_notes, my_notes=names, my_privacy=privacies,
                               my_note_id=note_ids)
    else:
        return make_response("You are not logged in!", 400)


@app.route("/viewnote/<int:noteid>", methods=["GET"])
def viewnote(noteid):
    sql.execute(
        "SELECT notes.noteid, notes.login, notes.notename, notes.content, notes.privacy FROM notes WHERE notes.noteid = %(noteid)s",
        {'noteid': noteid})
    note = sql.fetchone()
    if note[4] == 'private' or note[4] == 'secure':
        if session.get('identity') is not None:
            login = session.get('identity')
            if login != note[1]:
                return make_response("You are not authorized to access this note.", 401)
        else:
            return make_response("You are not logged in!", 400)
    return render_template("viewnote.html", note_name=note[2], note_privacy=note[4], note_id=note[0],
                           note_content=note[3])


@app.route("/unlock/<int:noteid>", methods=["POST"])
def unlocknote(noteid):
    if session.get('identity') is not None:
        login = session.get('identity')
        password = request.form.get("note-password").encode()
        if password is None:
            return make_response("No password supplied", 400)
        sql.execute("SELECT password FROM notes WHERE noteid = %(noteid)s", {'noteid': noteid})
        db_password, = sql.fetchone() or (None,)
        db_password = db_password.encode()
        if db_password is None:
            return make_response("No such note", 400)
        if not checkpw(password, db_password):
            return make_response("Invalid password", 400)
        sql.execute(
            "SELECT notes.noteid, notes.login, notes.notename, notes.content, notes.privacy, notes.nonce FROM notes WHERE notes.noteid = %(noteid)s",
            {'noteid': noteid})
        note = sql.fetchone()
        if login != note[1]:
            return make_response("You are not authorized to access this note.", 401)
        note_text = decrypt(note[3], note[5])
        return render_template("viewnote.html", note_name=note[2], note_privacy="unlocked secure", note_id=note[0],
                               note_content=note_text)
    else:
        return make_response("You are not logged in!", 400)


@app.route("/publicnotes", methods=["GET"])
def viewpublicnotes():
    sql.execute(
        "SELECT notes.login, notes.notename, notes.privacy, notes.noteid FROM notes WHERE notes.privacy = 'public'")
    notes = sql.fetchall()
    num_of_notes = len(notes)
    logins = []
    names = []
    note_ids = []
    for i in range(num_of_notes):
        note = notes[i]
        logins.append(note[0])
        names.append(note[1])
        note_ids.append(note[3])
    return render_template("publicnotelist.html", num_of_notes=num_of_notes, my_notes=names, my_logins=logins,
                           my_note_id=note_ids)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload-file", methods=['POST'])
def upload_file():
    if session.get('identity') is not None:
        login = session.get('identity')
        if 'file' not in request.files:
            return {"message": "No file part"}, 404
        file = request.files["file"]
        app.logger.debug(file)
        if file.filename == '':
            return {"message": "No file"}, 404
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            sql.execute(
                "INSERT INTO files(filename, login) VALUES(%(filename)s, %(login)s)",
                {'filename': filename, 'login': login})
            return {"message": "Uploaded file"}, 200
        else:
            return {"message": "Invalid file"}, 400
    else:
        return make_response("You are not logged in!", 400)


@app.route("/download-file/<int:file_id>", methods=['GET'])
def download_file(file_id):
    if session.get('identity') is not None:
        sql.execute("SELECT fileid, filename, login FROM files WHERE fileid=%(file_id)s", {'file_id': file_id})
        file = sql.fetchone()
        if file is None:
            return make_response("File couldn't be found on server.", 400)
        dblogin = file[2]
        login = session.get('identity')
        if dblogin != login:
            return make_response("You are not authorized to access this file.", 401)
        filename = file[1]
        filepath = "files/" + filename
        if filepath is not None:
            try:
                return send_file(filepath, attachment_filename=filename, as_attachment=True)
            except Exception as e:
                print(e)
                return make_response("File couldn't be found on server.", 400)

        return filename, 200
    else:
        return make_response("You are not logged in!", 400)


@app.route("/filelist", methods=["GET"])
def filelist():
    if session.get('identity') is not None:
        login = session.get('identity')
        sql.execute(
            "SELECT fileid, filename FROM files WHERE login = %(login)s",
            {'login': login})
        files = sql.fetchall()
        num_of_files = len(files)
        filenames = []
        file_ids = []
        for i in range(num_of_files):
            file = files[i]
            filenames.append(file[1])
            file_ids.append(file[0])
        return render_template("fileslist.html", num_of_files=num_of_files, my_filenames=filenames,
                               my_file_id=file_ids)
    else:
        return make_response("You are not logged in!", 400)


@app.route("/forgot-password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == "POST":
        login = request.form.get("login")
        sql.execute("SELECT email FROM users WHERE login = %(login)s", {'login': login})
        email, = sql.fetchone() or (None,)
        if email is None:
            make_response("No account tied to this login.", 400)
        recovery_id = uuid.uuid4().hex
        cache.set(f'{recovery_id}', login, timeout=300)
        return make_response(
            f"Sending email to: {email}\n    \n     \n"
            f"Visit this link to recover your password: https://localhost/recover-password/{recovery_id}",
            200)
    else:
        return render_template("recoverpassword.html")


@app.route("/recover-password/<recovery_id>", methods=['GET', 'POST'])
def change_password(recovery_id):
    login = cache.get(f'{recovery_id}')
    if login is None:
        return make_response("Invalid link.", 400)
    if request.method == "POST":
        new_password = request.form.get('password')
        repeated_password = request.form.get('repeat-password')
        if new_password != repeated_password:
            make_response("Passwords do not match", 400)
        hashed_new_password = hashpw(new_password.encode(), salt)
        sql.execute("UPDATE users SET password = %(hashed_new_password)s WHERE login = %(login)s",
                    {'hashed_new_password': hashed_new_password, 'login': login})
        cache.set(f'{login}Attempts', 0)
        sql.execute("DELETE * FROM ips WHERE login = %(login)s", {'login': login})
        ip = request.access_route
        add_new_ip_to_user(ip, login)
        return make_response("Changed password.", 200)
    else:
        return render_template("changepassword.html", recovery_id=recovery_id)
