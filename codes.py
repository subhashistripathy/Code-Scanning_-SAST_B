import os
import sqlite3
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

# Hard-coded secret (Credential Exposure)
API_KEY = "sk_test_123456_secret_key_exposed"

# Weak password hashing
def store_password(user, pwd):
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    with open("users.txt", "a") as f:
        f.write(f"{user}:{hashed}\n")


# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return cur.execute(query).fetchall()


# Command Injection
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    return os.popen("ping -c 1 " + ip).read()


# Insecure HTTP request (No SSL Verification)
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    r = requests.get(url, verify=False)
    return r.text


# Path Traversal
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    return open("/var/data/" + filename, "r").read()


# Debug mode enabled
if __name__ == "__main__":
    app.run(debug=True)
