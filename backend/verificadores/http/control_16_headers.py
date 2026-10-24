"""Verificador HTTP para Control 16: Headers de seguridad esenciales."""

import time
import urllib.error
import urllib.request
from typing import Dict, List
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "16"
NOMBRE = "Cabeceras de seguridad HTTP esenciales (HSTS, CSP, nosniff, etc.)"

EXPECTED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


def verificar_headers(url: str, timeout: int = 10) -> ResultadoVerificacion:
    """Inspecciona las cabeceras HTTP de respuesta para verificar protecciones estándar."""
    inicio = time.monotonic()
    curl_cmd = f'curl -s -I "{url}"'

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityControlCenter-AuditProbe/1.0"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers: Dict[str, str] = {k: v for k, v in resp.headers.items()}
            status_code = resp.status
    except urllib.error.HTTPError as exc:
        headers = {k: v for k, v in exc.headers.items()}
        status_code = exc.code
    except Exception as exc:
        duracion = int((time.monotonic() - inicio) * 1000)
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="requiere evidencia",
            detalles=f"No se pudo conectar al endpoint para inspeccionar cabeceras ({exc}); se requiere evidencia.",
            evidencia=f"Comando ejecutado: {curl_cmd}\nError: {exc}",
            objetivo=url,
            duracion_ms=duracion,
        )

    duracion = int((time.monotonic() - inicio) * 1000)

    # Identificar cuáles están presentes y cuáles faltan
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}
    presentes: List[str] = []
    faltantes: List[str] = []

    for expected in EXPECTED_SECURITY_HEADERS:
        if expected.lower() in headers_lower:
            orig_name, val = headers_lower[expected.lower()]
            presentes.append(f"{orig_name}: {val}")
        else:
            faltantes.append(expected)

    evidencia_texto = (
        f"$ {curl_cmd}\n"
        f"HTTP Status: {status_code}\n\n"
        f"Cabeceras de seguridad detectadas ({len(presentes)}/{len(EXPECTED_SECURITY_HEADERS)}):\n" +
        ("\n".join(f"- {p}" for p in presentes) if presentes else "(ninguna)") +
        "\n\nCabeceras faltantes:\n" +
        ("\n".join(f"- {f}" for f in faltantes) if faltantes else "(ninguna faltante)")
    )

    if not faltantes:
        estado = "cumple"
        detalles = "Todas las cabeceras de seguridad esperadas están configuradas correctamente."
    elif len(presentes) >= 3:
        estado = "parcial"
        detalles = f"Se detectaron {len(presentes)} de {len(EXPECTED_SECURITY_HEADERS)} cabeceras; faltan: {', '.join(faltantes)}."
    else:
        estado = "no cumple"
        detalles = f"Faltan la mayoría de las cabeceras de seguridad esenciales: {', '.join(faltantes)}."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="http",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=url,
        duracion_ms=duracion,
    )
