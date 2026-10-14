import sqlite3

def search_products(user_term):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # CWE-89: SQL Injection via string concatenation
    query = "SELECT * FROM Products WHERE name LIKE '%" + user_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()
