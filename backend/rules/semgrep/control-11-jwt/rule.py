# Control 11 (inventario v1.0): tokens JWT de duración corta (15-30 minutos)
import datetime
import jwt


def emitir(user, key):
    return jwt.encode(  # ruleid: py-jwt-long-exp-ctl11
        {"sub": user},
        key,
        expires_delta=datetime.timedelta(days=7),
    )


def emitir_horas(user, key):
    return jwt.encode(  # ruleid: py-jwt-long-exp-ctl11
        {"sub": user},
        key,
        expires_delta=timedelta(hours=4))


def decodificar_sin_verificar(token, key):
    claims = jwt.decode(  # ruleid: py-jwt-unverified-decode-ctl11
        token, key, options={"verify_signature": False})
    claims2 = jwt.decode(  # ruleid: py-jwt-unverified-decode-ctl11
        token, key, algorithms=["none"])
    return claims


def decodificar_sin_aud_iss(token, key):
    claims3 = jwt.decode(  # ruleid: py-jwt-decode-without-aud-iss-ctl11
        token, key)
    return claims3


# Casos seguros: exp de 15-30 minutos + validación de firma, aud e iss
def emitir_ok(user, key):
    return jwt.encode(
        {"sub": user},
        key,
        expires_delta=datetime.timedelta(minutes=30))


def decodificar_ok(token, key):
    return jwt.decode(
        token, key, algorithms=["HS256"], audience="api://app", issuer="https://idp.example.com")
