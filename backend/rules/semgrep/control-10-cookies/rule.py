# Casos que deben detectar (Control 10)
response.set_cookie("session", token, secure=False)  # ruleid: py-cookie-insecure-flags-ctl10
response.set_cookie("session", token, httponly=False)  # ruleid: py-cookie-insecure-flags-ctl10
response.set_cookie("session", token, samesite="None")  # ruleid: py-cookie-insecure-flags-ctl10

# Caso seguro: todos los flags de seguridad
response.set_cookie(
    "session", token, secure=True, httponly=True, samesite="Strict"
)
