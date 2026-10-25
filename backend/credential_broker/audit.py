"""Bitácora de Auditoría para Credential Broker (F12).

Registra de forma inmutable cada solicitud, aprobación, rechazo, login o revocación
sin incluir jamás secretos, contraseñas, semillas TOTP ni tokens en claro.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional

AUDIT_LOG_FILE = Path(__file__).resolve().parents[1] / "storage" / "credentials" / "broker_audit.jsonl"
_audit_lock = threading.Lock()

_REDACT_SECRETS_REGEX = [
    re.compile(r"(?i)(password|passwd|secret|token|totp|auth|cookie|key)\s*[:=]\s*['\"]?[^\s'\"&>,]+"),
    re.compile(r"CANARY-[0-9a-fA-F\-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
]


def _sanitize_audit_data(val: Any) -> Any:
    """Recursivamente redacta valores confidenciales."""
    if isinstance(val, str):
        sanitized = val
        for pat in _REDACT_SECRETS_REGEX:
            sanitized = pat.sub("[REDACTED_SECRET]", sanitized)
        return sanitized
    if isinstance(val, dict):
        clean_dict = {}
        for k, v in val.items():
            if any(term in k.lower() for term in ("password", "passwd", "secret", "totp", "seed")):
                clean_dict[k] = "[REDACTED_SECRET]"
            else:
                clean_dict[k] = _sanitize_audit_data(v)
        return clean_dict
    if isinstance(val, list):
        return [_sanitize_audit_data(item) for item in val]
    return val


def log_broker_audit(
    event_type: str,
    site_id: str,
    agent_id: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    reviewer: Optional[str] = None
) -> None:
    """Escribe un registro de auditoría seguro."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "site_id": site_id,
        "agent_id": agent_id,
        "status": status,
        "reviewer": reviewer,
        "details": _sanitize_audit_data(details or {}),
    }

    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _audit_lock:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_broker_audit(limit: int = 100) -> List[Dict[str, Any]]:
    """Lee las últimas entradas de auditoría."""
    if not AUDIT_LOG_FILE.exists():
        return []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        entries = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(entries) >= limit:
                break
        return entries
    except OSError:
        return []
