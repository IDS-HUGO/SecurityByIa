def buscar(nombre):
    cursor.execute(f"SELECT * FROM users WHERE name = '{nombre}'")
    return cursor.fetchone()


def buscar_seguro(nombre):
    cursor.execute("SELECT * FROM users WHERE name = %s", (nombre,))
    return cursor.fetchone()
