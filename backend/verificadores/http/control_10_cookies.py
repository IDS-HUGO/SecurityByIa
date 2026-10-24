"""Verificador HTTP para Control 10: Banderas de las cookies (Secure, HttpOnly, SameSite)."""

import time
import urllib.error
import urllib.request
from typing import Any, List
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "10"
NOMBRE = "Cookies protegidas: Secure, HttpOnly y SameSite"


def _extract_cookies(headers: Any) -> List[str]:
    if hasattr(headers, "get_all"):
        return headers.get_all("Set-Cookie") or []
    if isinstance(headers, dict):
        val = headers.get("Set-Cookie") or headers.get("set-cookie")
        if isinstance(val, list):
            return val
        if val:
            return [str(val)]
    return []


def verificar_cookies(url: str, timeout: int = 10) -> ResultadoVerificacion:
    """Inspecciona las cabeceras Set-Cookie del objetivo buscando banderas de seguridad."""
    inicio = time.monotonic()
    curl_cmd = f'curl -s -I "{url}"'

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityControlCenter-AuditProbe/1.0"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_cookies = _extract_cookies(resp.headers)
            status_code = resp.status
    except urllib.error.HTTPError as exc:
        raw_cookies = _extract_cookies(exc.headers)
        status_code = exc.code
    except Exception as exc:
        duracion = int((time.monotonic() - inicio) * 1000)
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="requiere evidencia",
            detalles=f"No se pudo conectar al endpoint ({exc}); se requiere evidencia.",
            evidencia=f"Comando ejecutado: {curl_cmd}\nError: {exc}",
            objetivo=url,
            duracion_ms=duracion,
        )

    duracion = int((time.monotonic() - inicio) * 1000)

    evidencia_texto = (
        f"$ {curl_cmd}\n"
        f"HTTP Status: {status_code}\n"
        f"Cookies recibidas ({len(raw_cookies)}):\n" +
        ("\n".join(f"- {c}" for c in raw_cookies) if raw_cookies else "(No se recibieron cabeceras Set-Cookie en esta ruta)")
    )

    if not raw_cookies:
        # Si la ruta no emite cookies, no se asume 'cumple': se requiere evidencia del endpoint autenticado
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="requiere evidencia",
            detalles="La petición inicial no devolvió cabeceras Set-Cookie; se requiere evidencia de un endpoint de sesión/login.",
            evidencia=evidencia_texto,
            objetivo=url,
            duracion_ms=duracion,
        )

    problemas: List[str] = []
    for cookie in raw_cookies:
        cookie_lower = cookie.lower()
        partes = [p.strip() for p in cookie.split(";")]
        nombre_cookie = partes[0].split("=")[0] if partes else "cookie"

        if "secure" not in cookie_lower:
            problemas.append(f"Cookie '{nombre_cookie}' no tiene bandera 'Secure'")
        if "httponly" not in cookie_lower:
            problemas.append(f"Cookie '{nombre_cookie}' no tiene bandera 'HttpOnly'")
        if "samesite" not in cookie_lower:
            problemas.append(f"Cookie '{nombre_cookie}' no declara atributo 'SameSite'")

    if problemas:
        estado = "no cumple"
        detalles = f"Faltan banderas de protección en cookies: {'; '.join(problemas)}."
    else:
        estado = "cumple"
        detalles = "Todas las cookies inspeccionadas incluyen Secure, HttpOnly y SameSite."

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
