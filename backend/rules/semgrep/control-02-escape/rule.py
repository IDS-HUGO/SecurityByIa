# Casos que deben detectar (Control 2)
import textwrap
from fastapi.responses import HTMLResponse

cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # ruleid: py-sql-concat-ctl2
cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # ruleid: py-sql-concat-ctl2
session.execute(text(f"SELECT * FROM orders WHERE id = {oid}"))  # ruleid: py-sql-concat-ctl2
return HTMLResponse(f"<h1>Hola {nombre}</h1>")  # ruleid: py-html-response-var-ctl2

# Caso que debe detectar (Vue, regla generic sobre texto): v-html sin sanitizar
vue_template = '<div v-html="comentarioUsuario"></div>'  # ruleid: generic-vue-v-html-ctl2

# Casos seguros: consultas parametrizadas y HTML sin interpolación
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
session.execute(text("SELECT * FROM orders WHERE id = :oid"), {"oid": oid})
return HTMLResponse("<h1>Bienvenido</h1>")
