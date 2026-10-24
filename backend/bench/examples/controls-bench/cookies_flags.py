def iniciar_sesion(respuesta, token):
    respuesta.set_cookie("session", token, secure=False)
    respuesta.set_cookie("session-ok", token, secure=True, httponly=True, samesite="Strict")
    respuesta.set_cookie("prefs", "dark")
