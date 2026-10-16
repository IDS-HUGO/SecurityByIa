"""Caso de prueba 3: algoritmo criptográfico roto (CWE-327).

Archivo de datos del benchmark: NO debe ejecutarse nunca.
"""
import hashlib


def hash_password(password: str) -> str:
    # Vulnerable: MD5 no es apto para almacenar contraseñas.
    return hashlib.md5(password.encode()).hexdigest()
