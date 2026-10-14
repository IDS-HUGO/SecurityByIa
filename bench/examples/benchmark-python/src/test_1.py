"""Caso de prueba 1: inyección de comandos del sistema (CWE-78).

Archivo de datos del benchmark: NO debe ejecutarse nunca.
"""
import os


def run_ping(host: str) -> int:
    # Vulnerable: el comando se construye con entrada no confiable.
    return os.system("ping -c 1 " + host)
