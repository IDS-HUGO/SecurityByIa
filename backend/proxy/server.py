"""Proxy de secretos y APIs (F8): reverse proxy para proveedores de modelos.

Inyecta la clave del proveedor según la ruta (/gemini/..., /openai/...,
/claude/...), permite solo destinos de la lista blanca (los tres proveedores
con sus rutas permitidas), redacta secretos en respuestas y mensajes de error,
limita la tasa por token, guarda auditoría sin secretos y falla cerrado ante
cualquier incertidumbre (token inválido, destino fuera de lista, ruta no
permitida, secreto ausente, upstream caído).

Los agentes del demo autentican con un token limitado guardado SOLO como hash
SHA-256 en PROXY_TOKENS_FILE (o PROXY_TOKENS como JSON en el entorno); el valor
en claro del token nunca toca disco. La rotación es reemplazar el hash del
token en el archivo: el token anterior muere de inmediato.

El código que atraviesa el proxy es dato, nunca instrucciones: el proxy solo
reenvía JSON y no registra cuerpos.
"""

import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parents[1]
PROXY_TOKENS_FILE = os.environ.get(
    "PROXY_TOKENS_FILE", str(Path(__file__).resolve().parent / "tokens.json"))
AUDIT_FILE = Path(os.environ.get(
    "PROXY_AUDIT_FILE", str(ROOT / "storage" / "proxy_audit.jsonl")))
RATE_LIMIT_WINDOW_SECONDS = 60
UPSTREAM_TIMEOUT = 60

app = Flask(__name__)

# Lista blanca de destinos: proveedor → upstream, cabecera de autenticación y
# rutas permitidas. Cualquier destino fuera de esta tabla se rechaza (fail-closed).
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "key_env": "GEMINI_API_KEY",
        "auth_header": "x-goog-api-key",
        "auth_prefix": "",
        "allowed_paths": [r"^models/[\w.\-]+:(generateContent|countTokens)$"],
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "allowed_paths": [r"^chat/completions$", r"^completions$", r"^embeddings$"],
    },
    "claude": {
        "base_url": "https://api.anthropic.com/v1",
        "key_env": "ANTHROPIC_API_KEY",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        "allowed_paths": [r"^messages$"],
    },
}

_REDACT_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?[^\s'\"&>,]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
]

_rate_lock = threading.Lock()
_rate_hits: Dict[str, List[float]] = {}
_audit_lock = threading.Lock()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load_tokens() -> List[Dict[str, Any]]:
    """Carga los tokens limitados: solo hashes SHA-256, id, proveedores y tope
    de tasa. Acepta PROXY_TOKENS (JSON en el entorno) o PROXY_TOKENS_FILE."""
    raw = os.environ.get("PROXY_TOKENS", "")
    if raw.strip():
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
    try:
        with open(PROXY_TOKENS_FILE, "r", encoding="utf-8") as handle:
            data = json.loads(handle.read())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _authenticate(authorization_header: str) -> Optional[Dict[str, Any]]:
    """Valida 'Authorization: Bearer <token>' contra los hashes del archivo.
    El token en claro jamás se guarda ni se registra."""
    if not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):].strip()
    if not token:
        return None
    token_hash = _hash_token(token)
    for entry in _load_tokens():
        if not isinstance(entry, dict):
            continue
        if hmac.compare_digest(str(entry.get("token_sha256", "")), token_hash):
            return entry
    return None


def _rate_limit_ok(token_id: str, limit_per_minute: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        hits = [stamp for stamp in _rate_hits.get(token_id, [])
                if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
        if len(hits) >= max(1, limit_per_minute):
            _rate_hits[token_id] = hits
            return False
        hits.append(now)
        _rate_hits[token_id] = hits
        return True


def _redact_text(text: str, secret: Optional[str] = None) -> str:
    """Redacta el valor del secreto inyectado y patrones genéricos de claves."""
    output = str(text or "")
    if secret:
        output = output.replace(secret, "[REDACTED]")
    for pattern in _REDACT_PATTERNS:
        output = pattern.sub("[REDACTED]", output)
    return output


def _audit(token_id: Optional[str], provider: Optional[str], route: str,
           status_code: int, result: str, duration_ms: int) -> None:
    """Auditoría JSONL sin secretos ni cuerpos: fecha, servicio, ruta, resultado
    y token que hizo la llamada."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "token_id": token_id,
        "service": provider,
        "route": route,
        "status_code": status_code,
        "result": result,
        "duration_ms": duration_ms,
    }
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _audit_lock:
            with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # la auditoría jamás rompe la respuesta


def read_audit_entries(limit: int = 50) -> List[Dict[str, Any]]:
    """Últimas entradas de auditoría (para la vista de auditoría del dashboard)."""
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    entries = []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(entry)
        if len(entries) >= max(1, min(limit, 200)):
            break
    return entries


def status_snapshot() -> Dict[str, Any]:
    """Estado del proxy para el indicador del dashboard (sin secretos)."""
    url = os.environ.get("SECURITY_PROXY_URL", "").strip()
    configured = bool(url)
    reachable: Optional[bool] = None
    if configured:
        try:
            with urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=1.5) as response:
                reachable = response.status == 200
        except Exception:
            reachable = False
    return {
        "configured": configured,
        "reachable": reachable,
        "token_configured": bool(os.environ.get("SECURITY_PROXY_TOKEN", "").strip()),
        "providers": sorted(PROVIDERS.keys()),
        "status": "ok" if reachable else ("down" if configured else "unconfigured"),
    }


app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "providers": sorted(PROVIDERS.keys())})


@app.post("/<provider>/<path:subpath>")
def forward(provider: str, subpath: str):
    started = time.monotonic()
    route = f"{provider}/{subpath}"

    def elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    token_record = _authenticate(request.headers.get("Authorization", ""))
    if token_record is None:
        _audit(None, provider, route, 401, "denied:invalid-token", elapsed())
        return jsonify({"error": "Token de proxy inválido."}), 401
    token_id = str(token_record.get("id", "unknown"))

    provider_config = PROVIDERS.get(provider)
    if not provider_config:
        _audit(token_id, provider, route, 403, "denied:destination-not-whitelisted", elapsed())
        return jsonify({"error": "Destino fuera de la lista blanca del proxy."}), 403
    if provider not in (token_record.get("providers") or []):
        _audit(token_id, provider, route, 403, "denied:token-scope", elapsed())
        return jsonify({"error": "El token no tiene permiso para este proveedor."}), 403
    if not any(re.match(pattern, subpath) for pattern in provider_config["allowed_paths"]):
        _audit(token_id, provider, route, 403, "denied:path-not-allowed", elapsed())
        return jsonify({"error": "Ruta no permitida para este proveedor."}), 403
    if not _rate_limit_ok(token_id, int(token_record.get("rate_limit_per_minute", 30))):
        _audit(token_id, provider, route, 429, "denied:rate-limit", elapsed())
        return jsonify({"error": "Límite de tasa del token excedido."}), 429

    secret = os.environ.get(provider_config["key_env"], "")
    if not secret:
        _audit(token_id, provider, route, 503, "denied:secret-not-configured", elapsed())
        return jsonify({"error": f"El proxy no tiene configurada la clave para {provider}."}), 503

    headers: Dict[str, str] = {"Content-Type": "application/json",
                               provider_config["auth_header"]:
                                   provider_config["auth_prefix"] + secret}
    headers.update(provider_config.get("extra_headers", {}))
    upstream_url = provider_config["base_url"] + "/" + subpath
    upstream_request = urllib.request.Request(
        upstream_url,
        data=request.get_data(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(upstream_request, timeout=UPSTREAM_TIMEOUT) as response:
            status_code = response.status
            raw_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8", errors="replace")[:4000]
        status_code = exc.code
    except Exception as exc:
        message = _redact_text(f"Upstream no disponible: {exc}", secret=secret)
        _audit(token_id, provider, route, 502, "denied:upstream-error", elapsed())
        return jsonify({"error": message}), 502

    _audit(token_id, provider, route, status_code, "allowed", elapsed())
    return app.response_class(_redact_text(raw_body, secret=secret),
                              status=status_code, mimetype="application/json")


def main() -> None:
    app.run(
        host=os.environ.get("PROXY_HOST", "127.0.0.1"),
        port=int(os.environ.get("PROXY_PORT", "5001")),
        debug=False,
    )


if __name__ == "__main__":
    main()
