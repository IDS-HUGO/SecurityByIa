import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)
api_key = "admin123"  # vuln-line: 6 (CWE-798)

@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password", "")
    # CWE-327: Broken Crypto
    p_hash = hashlib.md5(password.encode()).hexdigest()  # vuln-line: 12
    return p_hash

@app.route("/user")
def get_user():
    user = request.args.get("id")
    # CWE-89: SQL Injection
    query = f"SELECT * FROM accounts WHERE id = {user}"  # vuln-line: 18
    return query

@app.route("/execute")
def run_code():
    code = request.args.get("code", "")
    # CWE-94: Code Injection
    return str(eval(code))  # vuln-line: 24
