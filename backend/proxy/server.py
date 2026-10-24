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
import subprocess
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

# Lista permitida de comandos de solo lectura para el modo nube
ALLOWED_CLOUD_COMMAND_PREFIXES = (
    "aws rds describe-db-clusters",
    "aws rds describe-db-instances",
    "aws s3api get-bucket-policy-status",
    "aws s3api get-public-access-block",
    "aws s3api get-bucket-acl",
    "aws s3api get-bucket-lifecycle-configuration",
    "aws elbv2 describe-listeners",
    "aws elbv2 describe-load-balancers",
    "aws elb describe-load-balancers",
    "aws cloudtrail describe-trails",
    "aws cloudtrail get-trail-status",
    "aws backup describe-backup-vault",
    "aws backup list-recovery-points-by-backup-vault",
)

DISALLOWED_CLOUD_WORDS = (
    "delete", "put", "create", "update", "modify", "terminate", "stop",
    "start", "reboot", "attach", "detach", "authorize", "revoke", "set-",
    "add", "remove", "restore", "copy", "import", "export", "run-", "apply",
)

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


@app.get("/")
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


def is_cloud_command_allowed(command: Any) -> tuple[bool, str]:
    """Verifica si un comando o lista de argumentos coincide con la lista permitida de describe/get."""
    if isinstance(command, list):
        cmd_str = " ".join(str(c) for c in command).strip()
    else:
        cmd_str = str(command or "").strip()

    cmd_lower = cmd_str.lower()
    # No permitir comandos vacíos
    if not cmd_lower:
        return False, "Comando vacío."

    # Debe iniciar con un prefijo permitido
    starts_with_allowed = any(cmd_lower.startswith(prefix) for prefix in ALLOWED_CLOUD_COMMAND_PREFIXES)
    if not starts_with_allowed:
        return False, "Comando no permitido: el modo nube solo acepta comandos describe y get de la lista permitida."

    # No debe contener subcomandos ni flags de mutación
    tokens = cmd_lower.split()
    for word in DISALLOWED_CLOUD_WORDS:
        for token in tokens:
            if token == word or token == f"--{word}" or token.startswith(f"--{word}="):
                return False, f"Parámetro o subcomando peligroso no permitido: {word}"

    return True, cmd_str


@app.post("/cloud/execute")
def execute_cloud_command():
    started = time.monotonic()
    route = "cloud/execute"

    def elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    token_record = _authenticate(request.headers.get("Authorization", ""))
    if token_record is None:
        _audit(None, "cloud", route, 401, "denied:invalid-token", elapsed())
        return jsonify({"error": "Token de proxy inválido."}), 401
    token_id = str(token_record.get("id", "unknown"))

    # Validar scope de proveedor si el token declara lista de proveedores
    providers = token_record.get("providers") or []
    if providers and not any(p in providers for p in ("cloud", "aws", "gemini", "all")):
        _audit(token_id, "cloud", route, 403, "denied:token-scope", elapsed())
        return jsonify({"error": "El token no tiene permiso para ejecutar comandos en la nube."}), 403

    if not _rate_limit_ok(token_id, int(token_record.get("rate_limit_per_minute", 30))):
        _audit(token_id, "cloud", route, 429, "denied:rate-limit", elapsed())
        return jsonify({"error": "Límite de tasa del token excedido."}), 429

    payload = request.get_json(silent=True) or {}
    command = payload.get("command")
    if not command:
        _audit(token_id, "cloud", route, 400, "denied:missing-command", elapsed())
        return jsonify({"error": "Falta el comando a ejecutar."}), 400

    allowed, clean_or_err = is_cloud_command_allowed(command)
    if not allowed:
        _audit(token_id, "cloud", route, 403, "denied:command-not-allowlisted", elapsed())
        return jsonify({"error": clean_or_err}), 403

    cmd_tokens = command if isinstance(command, list) else command.split()

    # Inyección de credenciales de nube estrictamente en el entorno del proceso
    env = os.environ.copy()
    creds = payload.get("credentials") or {}
    if creds.get("aws_access_key_id"):
        env["AWS_ACCESS_KEY_ID"] = creds["aws_access_key_id"]
    if creds.get("aws_secret_access_key"):
        env["AWS_SECRET_ACCESS_KEY"] = creds["aws_secret_access_key"]
    if creds.get("aws_session_token"):
        env["AWS_SESSION_TOKEN"] = creds["aws_session_token"]
    if creds.get("aws_default_region"):
        env["AWS_DEFAULT_REGION"] = creds["aws_default_region"]

    try:
        proc = subprocess.run(cmd_tokens, capture_output=True, text=True, timeout=20, env=env)
        stdout = _redact_text(proc.stdout)
        stderr = _redact_text(proc.stderr)
        exit_code = proc.returncode
    except FileNotFoundError:
        stdout = ""
        stderr = "aws cli no se encuentra instalado en el host del proxy"
        exit_code = 127
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = "Tiempo de espera agotado al ejecutar comando de nube"
        exit_code = 124
    except Exception as exc:
        stdout = ""
        stderr = _redact_text(str(exc))
        exit_code = 1

    _audit(token_id, "cloud", route, 200 if exit_code == 0 else 502,
           "allowed" if exit_code == 0 else "allowed:error", elapsed())
    return jsonify({
        "status": "ok" if exit_code == 0 else "error",
        "command": clean_or_err,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }), (200 if exit_code == 0 else 200)


# --- F8 Extension: Acceso Delegado a Webs Privadas para Agentes ---

@app.post("/delegated/session/create")
def create_delegated_session():
    """Permite a un agente solicitar un token de sesión efímero para un sitio."""
    token_record = _authenticate(request.headers.get("Authorization", ""))
    if token_record is None:
        return jsonify({"error": "Token de proxy inválido."}), 401

    payload = request.get_json(silent=True) or {}
    site_id = payload.get("site_id")
    if not site_id:
        return jsonify({"error": "Falta site_id."}), 400

    from proxy.delegated_auth import DelegatedAuthVault, log_delegated_audit
    vault = DelegatedAuthVault()
    try:
        session_info = vault.create_ephemeral_session(
            site_id=site_id,
            agent_id=str(token_record.get("id", "agent")),
            ttl_seconds=payload.get("ttl_seconds", 1800),
        )
        log_delegated_audit(
            agent_id=str(token_record.get("id", "agent")),
            site_id=site_id,
            action="session_created",
            status="success",
            details={"session_id": session_info["session_id"]},
        )
        return jsonify({"status": "ok", "session": session_info}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.post("/delegated/session/login")
def execute_delegated_login():
    """Ejecuta el login de confianza inyectando credenciales y TOTP sin exponerlos al agente."""
    token_record = _authenticate(request.headers.get("Authorization", ""))
    if token_record is None:
        return jsonify({"error": "Token de proxy inválido."}), 401

    payload = request.get_json(silent=True) or {}
    delegated_token = payload.get("delegated_token")
    login_url = payload.get("login_url")
    if not delegated_token or not login_url:
        return jsonify({"error": "Faltan delegated_token o login_url."}), 400

    from proxy.delegated_auth import DelegatedAuthVault, TrustedBrowserLoginAutomator, log_delegated_audit
    vault = DelegatedAuthVault()
    sess = vault.validate_session(delegated_token)
    if not sess:
        return jsonify({"error": "Sesión delegada inválida o expirada."}), 403

    automator = TrustedBrowserLoginAutomator(vault)
    try:
        auth_res = automator.perform_login_flow(sess["site_id"], login_url)
        # Se guarda el estado en el vault y se devuelve solo confirmación y headers opaque
        vault.update_session_state(sess["session_id"], cookies={"session_id": auth_res.get("session_cookie", "")})
        log_delegated_audit(
            agent_id=sess["agent_id"],
            site_id=sess["site_id"],
            action="login_performed",
            status="success",
            details={"session_id": sess["session_id"]},
        )
        return jsonify({
            "status": "authenticated",
            "session_id": sess["session_id"],
            "authenticated": True,
            "message": "Login delegado ejecutado exitosamente. Credenciales inyectadas de forma segura."
        }), 200
    except Exception as e:
        log_delegated_audit(
            agent_id=sess["agent_id"],
            site_id=sess["site_id"],
            action="login_performed",
            status="error",
            details={"error": str(e)},
        )
        return jsonify({"error": f"Fallo al ejecutar login delegado: {str(e)}"}), 502


@app.post("/delegated/session/revoke")
def revoke_delegated_session():
    """Revoca inmediatamente la sesión delegada."""
    token_record = _authenticate(request.headers.get("Authorization", ""))
    if token_record is None:
        return jsonify({"error": "Token de proxy inválido."}), 401

    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id")
    if not session_id:
        return jsonify({"error": "Falta session_id."}), 400

    from proxy.delegated_auth import DelegatedAuthVault, log_delegated_audit
    vault = DelegatedAuthVault()
    ok = vault.revoke_session(session_id)
    log_delegated_audit(
        agent_id=str(token_record.get("id", "agent")),
        site_id="unknown",
        action="session_revoked",
        status="success" if ok else "not_found",
        details={"session_id": session_id},
    )
    return jsonify({"status": "ok", "revoked": ok}), 200



def main() -> None:
    app.run(
        host=os.environ.get("PROXY_HOST", "127.0.0.1"),
        port=int(os.environ.get("PROXY_PORT", "5001")),
        debug=False,
    )


if __name__ == "__main__":
    main()
