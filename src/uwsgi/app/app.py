from flask import Flask
import mysql.connector as mariadb
import os
import time
import app.init as dbinit
app = Flask(__name__, static_url_path="")
db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
sql = db.cursor(buffered=True)


@app.route("/", methods=["GET"])
def index():
    dbinit.init()
    sql.execute("USE od")
    sql.execute("SELECT * FROM users")
    data = sql.fetchall()
    print(data)
    return "Hello World!"
