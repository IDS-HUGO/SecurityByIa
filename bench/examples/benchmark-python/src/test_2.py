"""Caso de prueba 2: inyección SQL por concatenación (CWE-89).

Archivo de datos del benchmark: NO debe ejecutarse nunca.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    # Vulnerable: la consulta se arma concatenando entrada del usuario.
    query = "SELECT id, name FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
