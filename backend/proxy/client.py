"""Cliente del proxy de secretos para los agentes del demo.

Si SECURITY_PROXY_URL está configurada, TODAS las llamadas a proveedores de
modelos van por el proxy autenticando con el token limitado
(SECURITY_PROXY_TOKEN). El modo proxy falla cerrado: si el proxy no responde o
el token no está configurado, se lanza ProxyUnavailable y JAMÁS se recurre a la
clave del proveedor directamente (los agentes ni siquiera leen esa variable en
este modo). Sin proxy configurado, los agentes conservan su comportamiento
histórico (clave directa del entorno) para no romper despliegues existentes.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

PROXY_URL_ENV = "SECURITY_PROXY_URL"
PROXY_TOKEN_ENV = "SECURITY_PROXY_TOKEN"


class ProxyUnavailable(RuntimeError):
    """El proxy está configurado pero no responde o está mal configurado.
    El diseño es fail-closed: no hay fallback a la clave del proveedor."""


def proxy_configured() -> bool:
    """True si el entorno declara el proxy como puerta de salida de modelos."""
    return bool(os.environ.get(PROXY_URL_ENV, "").strip())


def model_request(provider: str, path: str, body: Optional[Dict[str, Any]],
                  timeout: int = 60) -> Any:
    """POST JSON al proveedor a través del proxy y devuelve el JSON de respuesta.

    Lanza ProxyUnavailable si el proxy está configurado y no responde o falta el
    token (nunca cae a la clave directa). Un error HTTP del proveedor (pasó por
    el proxy) se propaga como RuntimeError genérico con mensaje redactado.
    """
    if not proxy_configured():
        raise ProxyUnavailable("SECURITY_PROXY_URL no configurada.")
    base = os.environ[PROXY_URL_ENV].strip().rstrip("/")
    token = os.environ.get(PROXY_TOKEN_ENV, "").strip()
    if not token:
        raise ProxyUnavailable(
            "SECURITY_PROXY_TOKEN no configurada: el proxy exige un token limitado.")
    url = f"{base}/{provider}/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        data=json.dumps(body or {}, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace") or "null")
    except urllib.error.HTTPError as exc:
        exc.read()
        raise RuntimeError(
            f"El proveedor respondió {exc.code} vía proxy (revisá la petición).") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProxyUnavailable(f"El proxy no está disponible: {exc}") from exc


def cloud_execute(command: Any, credentials: Optional[Dict[str, str]] = None,
                  timeout: int = 30) -> Dict[str, Any]:
    """Ejecuta un comando de nube pasando por el proxy de secretos F8 (fail-closed).
    
    Lanza ProxyUnavailable si el proxy está configurado y no responde.
    Sin proxy configurado, si no hay credenciales o entorno, lanza RuntimeError.
    """
    if not proxy_configured():
        raise ProxyUnavailable("SECURITY_PROXY_URL no configurada: las credenciales de nube deben pasar por el proxy.")
    base = os.environ[PROXY_URL_ENV].strip().rstrip("/")
    token = os.environ.get(PROXY_TOKEN_ENV, "").strip()
    if not token:
        raise ProxyUnavailable(
            "SECURITY_PROXY_TOKEN no configurada: el proxy exige un token limitado.")
    url = f"{base}/cloud/execute"
    payload = {"command": command, "credentials": credentials or {}}
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            err_data = json.loads(raw)
            msg = err_data.get("error", raw)
        except Exception:
            msg = raw
        raise RuntimeError(f"Proxy cloud error ({exc.code}): {msg}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProxyUnavailable(f"El proxy no está disponible: {exc}") from exc

