import datetime
import jwt


def emitir(user, key):
    return jwt.encode(
        {"sub": user},
        key,
        expires_delta=datetime.timedelta(days=7),
    )


def emitir_ok(user, key):
    return jwt.encode(
        {"sub": user},
        key,
        expires_delta=datetime.timedelta(minutes=30),
    )
