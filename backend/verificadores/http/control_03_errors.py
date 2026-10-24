"""Verificador HTTP para Control 3: Errores sin información sensible."""

import re
import time
import urllib.error
import urllib.request
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "3"
NOMBRE = "Errores sin información sensible"

_SENSITIVE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r"django\.core\.exceptions", re.IGNORECASE),
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"Stack trace:", re.IGNORECASE),
    re.compile(r"NullPointerException", re.IGNORECASE),
    re.compile(r"SQLException|SQL syntax|pg_query\(\)", re.IGNORECASE),
    re.compile(r"internal server error at line \d+", re.IGNORECASE),
    re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"Exception Details:|An unhandled exception occurred", re.IGNORECASE),
]


def verificar_errores_sensibles(url: str, timeout: int = 10) -> ResultadoVerificacion:
    """Verifica si las respuestas de error del servidor filtran stack traces o datos sensibles."""
    inicio = time.monotonic()
    probe_url = url.rstrip("/") + "/_sec_probe_safe_404_test"
    req = urllib.request.Request(
        probe_url,
        headers={"User-Agent": "SecurityControlCenter-AuditProbe/1.0"},
        method="GET"
    )

    curl_cmd = f'curl -s -i "{probe_url}"'

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            body = resp.read().decode("utf-8", errors="replace")[:4000]
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        body = exc.read().decode("utf-8", errors="replace")[:4000]
    except Exception as exc:
        duracion = int((time.monotonic() - inicio) * 1000)
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="requiere evidencia",
            detalles=f"No se pudo conectar al endpoint para provocar error controlado ({exc}); se requiere evidencia.",
            evidencia=f"Comando ejecutado: {curl_cmd}\nError: {exc}",
            objetivo=url,
            duracion_ms=duracion,
        )

    duracion = int((time.monotonic() - inicio) * 1000)

    # Buscar patrones sensibles en el cuerpo de error
    hallados = [p.pattern for p in _SENSITIVE_PATTERNS if p.search(body)]

    evidencia_texto = (
        f"$ {curl_cmd}\n"
        f"HTTP Status: {status_code}\n\n"
        f"Extracto del cuerpo de respuesta (primeros 500 caracteres):\n"
        f"{body[:500]}\n"
    )

    if hallados:
        estado = "no cumple"
        detalles = f"La respuesta de error filtra información interna sensible o stack traces: {', '.join(hallados[:3])}."
    else:
        estado = "cumple"
        detalles = f"Respuesta de error (código {status_code}) limpia; no se detectaron volcados de pila ni trazas sensibles."

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
