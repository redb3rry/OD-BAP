import mysql.connector as mariadb
import os


def init():
    db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
    sql = db.cursor()
    sql.execute("DROP DATABASE IF EXISTS od;")
    sql.execute("CREATE DATABASE od;")
    sql.execute("USE od;")

    sql.execute("DROP TABLE IF EXISTS users")
    sql.execute("CREATE TABLE users (login VARCHAR(20), email VARCHAR(30), password VARCHAR(200), PRIMARY KEY (login))")
    sql.execute("INSERT INTO users (login, email, password) VALUES ('test', 'test@gmail.com', 'test');")

    sql.execute("DROP TABLE IF EXISTS session;")
    sql.execute("CREATE TABLE session (sid VARCHAR(32), login VARCHAR(32), PRIMARY KEY(sid));")
    sql.execute("DELETE FROM session;")

    sql.execute("DROP TABLE IF EXISTS notes")
    sql.execute("CREATE TABLE notes (noteid int AUTO_INCREMENT,"
                "login VARCHAR(20), "
                "content LONGTEXT, "
                "public BOOLEAN, "
                "PRIMARY KEY (noteid), FOREIGN KEY (login) REFERENCES users(login))")
    sql.execute("INSERT INTO notes(login, content, public) VALUES ('test', 'this is a test note', TRUE)")
    db.commit()
