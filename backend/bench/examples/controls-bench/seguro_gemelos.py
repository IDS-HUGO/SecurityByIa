"""Archivo sin violaciones: gemelos seguros de cada patrón (mide FPR)."""
DEBUG = False
TRUSTED_ORIGINS = ["https://app.example.com"]


def consulta(nombre):
    cursor.execute("SELECT * FROM users WHERE name = %s", (nombre,))
    return cursor.fetchone()


def auditar(user_id):
    logger.info("evento de seguridad para user_id=%s", user_id)
    requests.post("https://hooks.example.com/fixed", json={})
