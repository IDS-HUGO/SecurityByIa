"""Verificador HTTP para Control 1: CORS minimizado (solo orígenes confiables)."""

import time
import urllib.error
import urllib.request
from typing import Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "1"
NOMBRE = "CORS minimizado: solo orígenes confiables"


def verificar_cors(url: str, timeout: int = 10) -> ResultadoVerificacion:
    """Comprueba CORS enviando una petición con un Origin ajeno y no confiable."""
    inicio = time.monotonic()
    untrusted_origin = "https://evil-untrusted-origin.example.com"
    req = urllib.request.Request(
        url,
        headers={
            "Origin": untrusted_origin,
            "User-Agent": "SecurityControlCenter-AuditProbe/1.0",
        },
        method="GET"
    )

    curl_cmd = f'curl -s -D - -H "Origin: {untrusted_origin}" "{url}"'

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
            detalles=f"No se pudo conectar al endpoint ({exc}); se requiere evidencia manual.",
            evidencia=f"Comando ejecutado: {curl_cmd}\nError: {exc}",
            objetivo=url,
            duracion_ms=duracion,
        )

    duracion = int((time.monotonic() - inicio) * 1000)
    acao = headers.get("Access-Control-Allow-Origin", "").strip()
    acac = headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    evidencia_texto = (
        f"$ {curl_cmd}\n"
        f"HTTP Status: {status_code}\n"
        f"Access-Control-Allow-Origin: {acao or '(ausente)'}\n"
        f"Access-Control-Allow-Credentials: {acac or '(ausente)'}\n\n"
        "Cabeceras completas:\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    )

    if acao == "*" and acac == "true":
        estado = "no cumple"
        detalles = "CORS inseguro: comodín '*' con credenciales habilitadas (Access-Control-Allow-Credentials: true)."
    elif acao == untrusted_origin and acac == "true":
        estado = "no cumple"
        detalles = f"CORS inseguro: el origen no confiable '{untrusted_origin}' se refleja con credenciales permitidas."
    elif acao == untrusted_origin:
        estado = "parcial"
        detalles = f"El origen ajeno '{untrusted_origin}' se refleja en Access-Control-Allow-Origin (sin credenciales)."
    elif acao == "*":
        estado = "parcial"
        detalles = "Access-Control-Allow-Origin es comodín '*', pero sin credenciales activadas."
    else:
        estado = "cumple"
        detalles = "Política CORS restrictiva: el origen no confiable fue rechazado o no se refleja."

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
