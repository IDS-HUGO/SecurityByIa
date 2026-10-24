"""Módulo principal de verificadores en vivo y evidencia (F11)."""

from .base import (
    ResultadoVerificacion,
    leer_bitacora,
    redactar_secretos,
    registrar_bitacora,
)
from .http.runner import ejecutar_verificadores_http
from .nube.allowlist import ALLOWED_COMMAND_PREFIXES, validar_comando_nube
from .nube.runner import ejecutar_verificadores_nube

__all__ = [
    "ResultadoVerificacion",
    "ejecutar_verificadores_http",
    "ejecutar_verificadores_nube",
    "registrar_bitacora",
    "leer_bitacora",
    "redactar_secretos",
    "validar_comando_nube",
    "ALLOWED_COMMAND_PREFIXES",
]
