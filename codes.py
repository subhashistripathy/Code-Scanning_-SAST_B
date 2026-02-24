from flask import Flask, request, jsonify, make_response
import base64
import jwt
import time
import xml.etree.ElementTree as ET
import logging
import shutil
import ftplib
import socket

app = Flask(__name__)

# 1. Hardcoded JWT Secret + No Expiry Validation
JWT_SECRET = "jwt_secret_unsafe"

@app.route("/token")
def generate_token():
    payload = {
        "user": request.args.get("user"),
        "iat": int(time.time())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

# 2. Broken Authentication (Trusting Client Input)
@app.route("/login")
def login():
    role = request.args.get("role")
    if role == "admin":
        return "Welcome Admin"
    return "Welcome User"

# 3. XML External Entity (XXE)
@app.route("/xml", methods=["POST"])
def parse_xml():
    xml_data = request.data.decode()
    root = ET.fromstring(xml_data)   # XXE vulnerable
    return root.tag

# 4. Insecure File Upload (No Validation)
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file.save("/uploads/" + file.filename)  # no checks
    return "Uploaded"

# 5. Information Disclosure via Error Messages
@app.route("/divide")
def divide():
    a = int(request.args.get("a"))
    b = int(request.args.get("b"))
    return str(a / b)  # stack trace leak
  
# 6. Insecure Cookie Flags
@app.route("/cookie")
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie("session", "abc123")  # no Secure / HttpOnly
    return resp
  
# 7. Log Injection
logging.basicConfig(filename="app.log", level=logging.INFO)

@app.route("/log")
def log_user():
    username = request.args.get("user")
    logging.info("User logged in: " + username)  # log injection
    return "Logged"
  
# 8. Arbitrary File Deletion
@app.route("/delete")
def delete_file():
    path = request.args.get("path")
    shutil.rmtree(path)  # no validation
    return "Deleted"
  
# 9. FTP Cleartext Credentials
def ftp_connect():
    ftp = ftplib.FTP("ftp.example.com")
    ftp.login("admin", "admin123")  # cleartext creds
    ftp.quit()
  
# 10. Unrestricted Socket Connection (SSRF-like)
@app.route("/connect")
def connect_host():
    host = request.args.get("host")
    s = socket.socket()
    s.connect((host, 80))
    s.send(b"GET / HTTP/1.1\r\n\r\n")
    data = s.recv(1024)
    return data.decode(errors="ignore")
  
# 11. Base64 “Encryption”
@app.route("/encode")
def encode_data():
    data = request.args.get("data")
    encoded = base64.b64encode(data.encode())
    return encoded.decode()

# 12. Missing Rate Limiting (Brute Force Risk)
@app.route("/otp")
def verify_otp():
    otp = request.args.get("otp")
    if otp == "123456":
        return "OTP Valid"
    return "Invalid OTP"
  
# 13. CORS Misconfiguration
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
  
# 14. IDOR (Insecure Direct Object Reference)
@app.route("/order")
def get_order():
    order_id = request.args.get("id")
    return jsonify({"order_id": order_id, "amount": "₹5000"})

# 15. No CSRF Protection
@app.route("/change-email", methods=["POST"])
def change_email():
    email = request.form.get("email")
    return f"Email changed to {email}"


if __name__ == "__main__":
    app.run()
