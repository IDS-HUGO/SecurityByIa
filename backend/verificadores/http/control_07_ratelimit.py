"""Verificador HTTP para Control 7: Límite de tasa con respuesta 429."""

import time
import urllib.error
import urllib.request
from typing import Dict, List
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "7"
NOMBRE = "Límite de tasa y protección contra abusos"


def verificar_rate_limit(url: str, burst_count: int = 10, timeout: int = 10) -> ResultadoVerificacion:
    """Envía una serie controlada y no destructiva de peticiones para verificar límite de tasa o cabeceras 429."""
    inicio = time.monotonic()
    curl_sample = f'for i in $(seq 1 {burst_count}); do curl -s -I "{url}"; sleep 0.05; done'

    statuses: List[int] = []
    ratelimit_headers_found: Dict[str, str] = {}
    hit_429 = False

    for i in range(burst_count):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"SecurityControlCenter-RateProbe/{i+1}"},
            method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                statuses.append(status)
                for k, v in resp.headers.items():
                    if any(token in k.lower() for token in ("ratelimit", "retry-after")):
                        ratelimit_headers_found[k] = v
        except urllib.error.HTTPError as exc:
            statuses.append(exc.code)
            for k, v in exc.headers.items():
                if any(token in k.lower() for token in ("ratelimit", "retry-after")):
                    ratelimit_headers_found[k] = v
            if exc.code == 429:
                hit_429 = True
                break
        except Exception as exc:
            duracion = int((time.monotonic() - inicio) * 1000)
            return ResultadoVerificacion(
                control_id=CONTROL_ID,
                nombre=NOMBRE,
                modo="http",
                estado="requiere evidencia",
                detalles=f"Error al contactar el objetivo durante prueba de tasa ({exc}); se requiere evidencia.",
                evidencia=f"Comando simulado: {curl_sample}\nError: {exc}",
                objetivo=url,
                duracion_ms=duracion,
            )
        # Pausa suave no destructiva (50 ms)
        time.sleep(0.05)

    duracion = int((time.monotonic() - inicio) * 1000)

    evidencia_texto = (
        f"$ {curl_sample}\n"
        f"Peticiones enviadas: {len(statuses)}\n"
        f"Códigos HTTP obtenidos: {statuses}\n"
        f"Cabeceras de límite de tasa detectadas:\n" +
        ("\n".join(f"{k}: {v}" for k, v in ratelimit_headers_found.items()) if ratelimit_headers_found else "(ninguna cabecera de ratelimit detectada)")
    )

    if hit_429:
        estado = "cumple"
        detalles = f"El endpoint respondió con HTTP 429 Too Many Requests tras {len(statuses)} peticiones."
    elif ratelimit_headers_found:
        estado = "cumple"
        detalles = f"Cabeceras de control de tasa presentes ({', '.join(ratelimit_headers_found.keys())})."
    else:
        # Por regla del requerimiento: si no se puede verificar plenamente, 'requiere evidencia', no 'cumple'
        estado = "requiere evidencia"
        detalles = (
            "No se disparó código 429 en la ráfaga no destructiva de baja frecuencia "
            "ni se detectaron cabeceras estándar; requiere evidencia de configuración en API Gateway o WAF."
        )

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
