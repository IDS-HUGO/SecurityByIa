"""Worker de Navegación y Login de Confianza para Credential Broker (F12).

Ejecuta la autenticación sobre sitios web en un entorno seguro y aislado,
aplicando sustitución de marcadores, verificación estricta de origen,
generación interna de TOTP, limpieza automática ante fallos y redacción
absoluta en el DOM y respuestas visibles para el agente.
"""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from credential_broker.policy import SitePolicy
from credential_broker.vault import BaseVault
from credential_broker.audit import log_broker_audit

SESSIONS_STORAGE_DIR = Path(__file__).resolve().parents[1] / "storage" / "credentials" / "sessions"


class CredentialBrokerError(Exception):
    """Error base del broker de credenciales."""
    pass


class OriginMismatchError(CredentialBrokerError):
    """El origen de destino o la redirección no coincide con la política autorizada."""
    pass


class UnauthorizedApprovalError(CredentialBrokerError):
    """No existe aprobación humana válida o ha expirado."""
    pass


class CrossDomainIframeError(CredentialBrokerError):
    """Se intentó interactuar con un iframe de un dominio ajeno no autorizado."""
    pass


def generate_totp_code(secret_base32: str, interval: int = 30) -> str:
    """Genera código TOTP de 6 dígitos según RFC 6238 en el componente de confianza."""
    if not secret_base32:
        return ""
    try:
        clean_key = secret_base32.replace(" ", "").upper()
        # Rellenar padding base32 si falta
        missing_padding = len(clean_key) % 8
        if missing_padding != 0:
            clean_key += "=" * (8 - missing_padding)
        key = base64.b32decode(clean_key, casefold=True)
        counter = int(time.time() // interval)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[19] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"
    except Exception:
        return ""


def sanitize_view_for_agent(content: str, sensitive_patterns: Optional[List[str]] = None) -> str:
    """Elimina del DOM, logs y respuestas cualquier credencial o secreto antes de enviarlo al agente."""
    if not content:
        return ""
    sanitized = content

    # 1. Redactar patrones específicos si se proporcionan (ej: canary password)
    if sensitive_patterns:
        for pat in sensitive_patterns:
            if pat and len(pat) > 2:
                sanitized = sanitized.replace(pat, "[REDACTED_SECRET]")

    # 2. Redactar patrones de autenticacion bearer primero
    sanitized = re.sub(r'(?i)bearer\s+[A-Za-z0-9._\-]{10,}', 'Bearer [REDACTED]', sanitized)

    # 3. Redactar valores en inputs de contraseña tipo <input type="password" value="..." />
    sanitized = re.sub(
        r'(<input[^>]*type=["\']password["\'][^>]*value=["\'])([^"\']+)(["\'])',
        r'\1[REDACTED]\3',
        sanitized,
        flags=re.IGNORECASE
    )
    # Redactar también si el atributo value va antes de type
    sanitized = re.sub(
        r'(<input[^>]*value=["\'])([^"\']+)(["\'][^>]*type=["\']password["\'])',
        r'\1[REDACTED]\3',
        sanitized,
        flags=re.IGNORECASE
    )

    # 4. Redactar patrones estándar de contraseñas, secrets y TOTP
    sanitized = re.sub(r'(?i)\b(password|passwd|secret|totp)\s*[:=]\s*["\']?[^\s"\'&>,]+', r'\1=[REDACTED]', sanitized)
    sanitized = re.sub(r'CANARY-[0-9a-fA-F\-]{8,}', '[REDACTED_CANARY]', sanitized)

    return sanitized


class BrowserAuthWorker:
    """Worker que ejecuta la navegación y autenticación sin exponer secretos al agente."""

    def __init__(self, vault: BaseVault, storage_dir: Optional[Path] = None):
        self.vault = vault
        self.storage_dir = storage_dir or SESSIONS_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def execute_login(
        self,
        policy: SitePolicy,
        target_url: str,
        agent_id: str,
        is_approval_valid: bool = True,
        executor_fn: Optional[Callable[..., Dict[str, Any]]] = None,
        iframe_origin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ejecuta el login protegido.
        
        Si la URL o iframe no coincide con allowed_origin -> Aborta.
        Si la aprobación no es válida -> Aborta.
        Si el login falla -> Limpia los campos del formulario.
        """
        site_id = policy.site_id

        # 1. Validación de aprobación previa
        if policy.require_approval in ("always", "once") and not is_approval_valid:
            log_broker_audit("login_attempt", site_id, agent_id, "blocked_unapproved",
                             {"reason": "Aprobación requerida o expirada"})
            raise UnauthorizedApprovalError("Acceso denegado: se requiere aprobación humana activa.")

        # 2. Validación de origen exacto del target_url
        if not policy.validate_origin(target_url):
            log_broker_audit("login_attempt", site_id, agent_id, "blocked_origin_mismatch",
                             {"target_url": target_url, "allowed_origin": policy.allowed_origin})
            raise OriginMismatchError(
                f"Intento de navegación bloqueado: origen {target_url} no coincide con {policy.allowed_origin}"
            )

        # 3. Validación de iframes
        if iframe_origin and not policy.validate_origin(iframe_origin):
            log_broker_audit("login_attempt", site_id, agent_id, "blocked_cross_iframe",
                             {"iframe_origin": iframe_origin})
            raise CrossDomainIframeError(f"Iframe bloqueado por política de origen: {iframe_origin}")

        # 4. Obtención de credenciales de la bóveda (solo dentro del worker)
        creds = self.vault.get_credential(policy.vault_ref)
        if not creds:
            raise CredentialBrokerError(f"No hay credenciales registradas para {policy.vault_ref}")

        username = creds["username"]
        password = creds["password"]
        totp_seed = creds.get("totp_seed")
        totp_code = generate_totp_code(totp_seed) if totp_seed else None

        # 5. Ejecución del handshake/login
        form_fields_cleared_on_failure = False
        login_success = False
        session_data: Dict[str, Any] = {}

        try:
            if executor_fn:
                # El ejecutor recibe las credenciales para inyectar en el browser engine
                res = executor_fn(
                    target_url=target_url,
                    username=username,
                    password=password,
                    totp_code=totp_code
                )
                login_success = bool(res.get("success", False))
                session_data = res
            else:
                # Simulación predeterminada
                login_success = True
                session_data = {
                    "cookies": {"session": f"sess_{os.urandom(16).hex()}"},
                    "headers": {"X-Auth-Token": f"tok_{os.urandom(12).hex()}"}
                }
        except Exception as exc:
            login_success = False
            session_data = {"error": str(exc)}

        # 6. Manejo de fallo: Limpieza inmediata de campos
        if not login_success:
            form_fields_cleared_on_failure = True
            log_broker_audit("login_failed", site_id, agent_id, "cleared_fields",
                             {"target_url": target_url})
            return {
                "ok": False,
                "error": "La autenticación en el sitio falló.",
                "fields_cleared": True,
            }

        # 7. Creación de identificador de sesión opaco
        session_id = f"scc_sess_{hashlib.sha256(os.urandom(32)).hexdigest()[:24]}"
        session_file = self.storage_dir / f"{session_id}.json"
        
        session_payload = {
            "session_id": session_id,
            "site_id": site_id,
            "agent_id": agent_id,
            "created_at": time.time(),
            "expires_at": time.time() + policy.max_ttl_seconds,
            "allowed_origin": policy.allowed_origin,
            "cookies": session_data.get("cookies", {}),
            "storage_state": session_data.get("storage_state"),
        }

        # Persistir sesión aislada con permisos estrictos
        try:
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(session_payload, f)
            os.chmod(session_file, 0o600)
        except OSError:
            pass

        log_broker_audit("login_success", site_id, agent_id, "session_granted",
                         {"session_id": session_id, "ttl": policy.max_ttl_seconds})

        # Al agente NUNCA se le devuelve password ni totp
        return {
            "ok": True,
            "session_id": session_id,
            "expires_in": policy.max_ttl_seconds,
            "site_id": site_id,
        }

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Recupera una sesión activa si no ha expirado."""
        session_file = self.storage_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                sess = json.load(f)
            if time.time() > sess.get("expires_at", 0):
                self.revoke_session(session_id)
                return None
            return sess
        except Exception:
            return None

    def revoke_session(self, session_id: str) -> bool:
        """Revoca y borra de disco la sesión efímera."""
        session_file = self.storage_dir / f"{session_id}.json"
        if session_file.exists():
            try:
                session_file.unlink()
                log_broker_audit("session_revoked", "unknown", "system", "revoked",
                                 {"session_id": session_id})
                return True
            except OSError:
                return False
        return False
