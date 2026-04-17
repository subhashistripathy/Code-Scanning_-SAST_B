import os
import sqlite3
import hashlib
import requests
import pickle
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, session
import jwt
import yaml
import logging

app = Flask(__name__)

# ── 1. Hardcoded Credentials (Critical) ───────────────────────────────────────
API_KEY = "sk_test_123456_secret_key_exposed"
DB_PASSWORD = "admin123"
SECRET_KEY = "supersecretkey123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
app.secret_key = "hardcoded_flask_secret"

# ── 2. Weak Password Hashing (High) ───────────────────────────────────────────
def store_password(user, pwd):
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    with open("users.txt", "a") as f:
        f.write(f"{user}:{hashed}\n")

# ── 3. SQL Injection (Critical) ───────────────────────────────────────────────
def get_user(username):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return cur.execute(query).fetchall()

def get_user_by_id(user_id):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    return cur.execute(query).fetchall()

# ── 4. Command Injection (Critical) ───────────────────────────────────────────
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    return os.popen("ping -c 1 " + ip).read()

@app.route("/traceroute")
def traceroute():
    host = request.args.get("host")
    result = subprocess.run(f"traceroute {host}", shell=True, capture_output=True, text=True)
    return result.stdout

# ── 5. No SSL Verification (High) ─────────────────────────────────────────────
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    r = requests.get(url, verify=False)
    return r.text

# ── 6. Path Traversal (High) ──────────────────────────────────────────────────
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    return open("/var/data/" + filename, "r").read()

@app.route("/download")
def download_file():
    filename = request.args.get("file")
    filepath = os.path.join("/uploads/", filename)
    with open(filepath, "rb") as f:
        return f.read()

# ── 7. Insecure Deserialization (Critical) ────────────────────────────────────
@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.get_data()
    obj = pickle.loads(data)              # arbitrary code execution possible
    return str(obj)

# ── 8. XML External Entity Injection — XXE (High) ─────────────────────────────
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()
    tree = ET.fromstring(xml_data)        # XXE not disabled
    return ET.tostring(tree)

# ── 9. JWT None Algorithm Attack (Critical) ───────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    token = jwt.encode(
        {"user": username, "admin": False},
        SECRET_KEY,
        algorithm="HS256"
    )
    return jsonify({"token": token})

@app.route("/admin")
def admin():
    token = request.headers.get("Authorization")
    decoded = jwt.decode(
        token,
        options={"verify_signature": False}   # signature not verified!
    )
    return jsonify(decoded)

# ── 10. YAML Deserialization (Critical) ───────────────────────────────────────
@app.route("/parse_yaml", methods=["POST"])
def parse_yaml():
    data = request.get_data()
    parsed = yaml.load(data)              # unsafe load — use yaml.safe_load
    return str(parsed)

# ── 11. Server-Side Request Forgery — SSRF (High) ─────────────────────────────
@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    r = requests.get(target)             # no allow-list, hits internal services
    return r.text

# ── 12. Insecure Temporary File (Medium) ──────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_data()
    tmp = tempfile.mktemp(suffix=".dat")  # race condition — use mkstemp
    with open(tmp, "wb") as f:
        f.write(data)
    return tmp

# ── 13. Hardcoded Admin Bypass (Critical) ─────────────────────────────────────
@app.route("/auth")
def auth():
    username = request.args.get("username")
    password = request.args.get("password")
    if username == "admin" and password == "password123":   # hardcoded backdoor
        session["authenticated"] = True
        return "Access granted"
    return "Access denied"

# ── 14. Sensitive Data in Logs (Medium) ───────────────────────────────────────
@app.route("/process")
def process():
    credit_card = request.args.get("cc_number")
    ssn         = request.args.get("ssn")
    logging.info(f"Processing payment for CC: {credit_card}, SSN: {ssn}")  # PII in logs!
    return "Processing"

# ── 15. Open Redirect (Medium) ────────────────────────────────────────────────
@app.route("/redirect")
def redirect_user():
    url = request.args.get("next")
    return f'<a href="{url}">Click here</a>'   # unvalidated redirect

# ── 16. Weak Random Token Generation (High) ───────────────────────────────────
import random
import string

@app.route("/reset_token")
def reset_token():
    token = ''.join(random.choices(string.ascii_letters, k=16))  # not cryptographically secure
    return jsonify({"reset_token": token})

# ── 17. Mass Assignment (High) ────────────────────────────────────────────────
@app.route("/update_user", methods=["POST"])
def update_user():
    data = request.get_json()
    conn = sqlite3.connect("test.db")
    cur  = conn.cursor()
    for key, value in data.items():                          # all fields blindly trusted
        cur.execute(f"UPDATE users SET {key} = '{value}'")  # SQL injection too!
    conn.commit()
    return "Updated"

# ── 18. Debug mode enabled (Medium) ───────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")   # exposed on all interfaces
