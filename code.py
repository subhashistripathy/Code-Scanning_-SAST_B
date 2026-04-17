import os
import re
import sqlite3
import hashlib
import subprocess
import secrets
import logging
from pathlib import Path
from flask import Flask, request, abort
import requests
from functools import wraps

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ── Credential: load from environment, never hardcoded ────────────────────────
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is not set")

# ── Strong password hashing with bcrypt ───────────────────────────────────────
try:
    import bcrypt
    def store_password(user: str, pwd: str) -> None:
        """Hash password with bcrypt (salted, slow) and persist securely."""
        hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
        # In production replace with a proper DB write; never a plain text file.
        conn = sqlite3.connect("users.db")
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (user, hashed.decode())
        )
        conn.commit()
        conn.close()

    def verify_password(user: str, pwd: str) -> bool:
        conn = sqlite3.connect("users.db")
        cur  = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (user,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return False
        return bcrypt.checkpw(pwd.encode(), row[0].encode())

except ImportError:
    logging.warning("bcrypt not installed; falling back to SHA-256+salt (install bcrypt for production)")
    def store_password(user: str, pwd: str) -> None:          # type: ignore[misc]
        salt   = secrets.token_hex(32)
        hashed = hashlib.sha256((salt + pwd).encode()).hexdigest()
        conn   = sqlite3.connect("users.db")
        cur    = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
            (user, salt, hashed)
        )
        conn.commit()
        conn.close()


# ── Parameterised query — no SQL injection ────────────────────────────────────
def get_user(username: str) -> list:
    """Return user rows for username using a parameterised query."""
    conn = sqlite3.connect("users.db")
    cur  = conn.cursor()
    # The (?,) tuple placeholder is never interpolated into SQL text.
    rows = cur.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchall()
    conn.close()
    return rows


# ── Allowed-host guard (reusable decorator) ───────────────────────────────────
ALLOWED_FETCH_HOSTS = {h.strip() for h in os.environ.get("ALLOWED_FETCH_HOSTS", "").split(",") if h.strip()}

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not secrets.compare_digest(key, API_KEY):
            abort(401)
        return f(*args, **kwargs)
    return decorated


# ── No command injection: allow-list + subprocess with no shell ───────────────
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

@app.route("/ping")
@require_api_key
def ping():
    ip = request.args.get("ip", "")
    if not IPV4_RE.match(ip):
        abort(400, "Invalid IP address")
    # Never shell=True; pass as a list so no shell interpretation occurs.
    result = subprocess.run(
        ["ping", "-c", "1", ip],
        capture_output=True, text=True, timeout=5
    )
    return result.stdout, 200, {"Content-Type": "text/plain"}


# ── SSL verification on; host allow-list enforced ─────────────────────────────
@app.route("/fetch")
@require_api_key
def fetch():
    from urllib.parse import urlparse
    url = request.args.get("url", "")
    parsed = urlparse(url)

    if parsed.scheme != "https":
        abort(400, "Only HTTPS URLs are permitted")
    if parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(403, "Host not in allow-list")

    try:
        r = requests.get(url, verify=True, timeout=10, allow_redirects=False)
        r.raise_for_status()
    except requests.RequestException as exc:
        logging.error("Fetch failed: %s", exc)
        abort(502, "Upstream request failed")

    return r.text


# ── Path traversal eliminated: resolve & jail inside BASE_DIR ─────────────────
BASE_DIR = Path("/var/data").resolve()

@app.route("/read")
@require_api_key
def read_file():
    filename = request.args.get("file", "")
    # Reject obvious traversal chars before even touching the filesystem.
    if ".." in filename or filename.startswith("/"):
        abort(400, "Invalid filename")

    target = (BASE_DIR / filename).resolve()

    # Confirm the resolved path is still inside BASE_DIR.
    if not target.is_relative_to(BASE_DIR):
        abort(400, "Access denied")
    if not target.is_file():
        abort(404, "File not found")

    return target.read_text()


# ── Debug mode off in production ──────────────────────────────────────────────
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
