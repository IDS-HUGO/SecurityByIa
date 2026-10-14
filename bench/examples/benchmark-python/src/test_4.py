"""Caso de prueba 4: caso seguro, consulta parametrizada (sin CWE).

Archivo de datos del benchmark: NO debe ejecutarse nunca.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    # Seguro: la consulta usa placeholders y no concatena entrada del usuario.
    cursor = conn.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    return cursor.fetchall()
