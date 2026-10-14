import os
import subprocess

# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
def get_user_input_command():
    """Vulnerable: directly uses user input in OS command"""
    user_input = input("Enter a filename: ")
    os.system("cat " + user_input)  # vuln-line: 7

# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
def vulnerable_sql_query():
    """Vulnerable: SQL injection"""
    user_id = input("Enter user ID: ")
    query = "SELECT * FROM users WHERE id = " + user_id  # vuln-line: 13

# CWE-94: Improper Control of Generation of Code ('Code Injection')
def eval_user_code():
    """Vulnerable: arbitrary code execution"""
    code = input("Enter Python code: ")
    eval(code)  # vuln-line: 19

# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
def insecure_hash():
    """Vulnerable: weak cryptographic algorithm"""
    import hashlib
    password = "secret"
    weak_hash = hashlib.md5(password.encode()).digest()  # vuln-line: 26

# CWE-798: Use of Hard-Coded Credentials
def connect_to_database():
    """Vulnerable: hardcoded credentials"""
    password = "admin123"  # vuln-line: 31
    db_connection = connect("localhost", "root", password)

def safe_sql_query(user_id):
    """Safe: parameterized query"""
    query = "SELECT * FROM users WHERE id = ?"
    execute(query, [user_id])
