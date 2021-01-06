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
    sql.execute(
        "INSERT INTO users (login, email, password) VALUES ('test', 'test@gmail.com', '$2y$12$4R0j8zl0sq8IwvFzZeLwIeb6c4Jbiil22o0GI5YKzhrkjLQw9dnPm');")

    sql.execute("DROP TABLE IF EXISTS session;")
    sql.execute("CREATE TABLE session (sid VARCHAR(32), login VARCHAR(32), PRIMARY KEY(sid));")
    sql.execute("DELETE FROM session;")

    sql.execute("DROP TABLE IF EXISTS notes")
    sql.execute("CREATE TABLE notes (noteid int AUTO_INCREMENT,"
                "login VARCHAR(20), "
                "notename VARCHAR(50),"
                "content LONGTEXT, "
                "privacy VARCHAR(10),"
                "password VARCHAR(200),"
                "nonce TEXT,"
                "PRIMARY KEY (noteid), FOREIGN KEY (login) REFERENCES users(login))")
    sql.execute("INSERT INTO notes(login, content, privacy, password) "
                "VALUES ('test', 'this is a test note', 'secure', 'password')")

    sql.execute("DROP TABLE IF EXISTS files")
    sql.execute(
        "CREATE TABLE files (fileid int AUTO_INCREMENT, filename VARCHAR(50), login VARCHAR(20), PRIMARY KEY (fileid), FOREIGN KEY (login) REFERENCES users(login))")
    db.commit()
