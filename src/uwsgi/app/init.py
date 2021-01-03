import mysql.connector as mariadb
import os


def init():
    db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
    sql = db.cursor()
    sql.execute("DROP DATABASE IF EXISTS od;")
    sql.execute("CREATE DATABASE od;")
    sql.execute("USE od;")

    sql.execute("DROP TABLE IF EXISTS users")
    sql.execute("CREATE TABLE users (login VARCHAR(20), email VARCHAR(30), password VARCHAR(200))")
    sql.execute("INSERT INTO users (login, email, password) VALUES ('test', 'test@gmail.com', 'test');")

    sql.execute("DROP TABLE IF EXISTS session;")
    sql.execute("CREATE TABLE session (sid VARCHAR(32), login VARCHAR(32), PRIMARY KEY(sid));")
    sql.execute("DELETE FROM session;")
    db.commit()
