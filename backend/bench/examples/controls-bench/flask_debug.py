from flask import Flask

app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)

# Caso seguro: DEBUG desactivado en producción (el dev server nunca va a producción;
# la verificación del control 3 es forzar errores y recibir mensajes genéricos).
app.config["DEBUG"] = False
