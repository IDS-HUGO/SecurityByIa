import os
import pickle
from flask import Flask, request

app = Flask(__name__)

# CWE-79: Cross-site Scripting (XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return "<h1>Search results for: " + query + "</h1>"  # vuln-line: 10

# CWE-22: Path Traversal
@app.route("/view")
def view_file():
    filename = request.args.get("file", "default.txt")
    with open("uploads/" + filename, "r") as f:  # vuln-line: 17
        return f.read()

# CWE-502: Insecure Deserialization
@app.route("/session")
def load_session():
    cookie = request.cookies.get("session_data")
    data = pickle.loads(cookie.encode())  # vuln-line: 24
    return str(data)

# CWE-798: Hardcoded Credentials
JWT_SECRET = "secret"  # vuln-line: 28

# Safe function (no vulnerabilities) to verify false positives
@app.route("/profile")
def safe_profile():
    user_id = 42
    return f"Profile ID: {user_id}"
