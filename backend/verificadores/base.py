"""Clases base, bitácora de auditoría y utilidades para verificadores en vivo."""

import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
BITACORA_FILE = Path(os.environ.get(
    "LIVE_VERIFICATION_AUDIT_FILE",
    str(ROOT / "storage" / "live_verification_audit.jsonl")
))

_bitacora_lock = threading.Lock()

_REDACT_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|auth)\s*[=:]\s*['\"]?[^\s'\"&>,]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"(?i)aws_secret_access_key\s*=\s*[^\s]+"),
]


def redactar_secretos(texto: Any) -> str:
    """Redacta cualquier secreto, token o credencial de las evidencias y registros."""
    cadena = str(texto or "")
    for pattern in _REDACT_PATTERNS:
        cadena = pattern.sub("[REDACTED_SECRET]", cadena)
    return cadena


@dataclass
class ResultadoVerificacion:
    control_id: str
    nombre: str
    modo: str  # "http" o "nube"
    estado: str  # "cumple", "parcial", "no cumple", "requiere evidencia"
    detalles: str
    evidencia: str
    objetivo: str
    timestamp: str = ""
    duracion_ms: int = 0
    requiere_evidencia: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.estado == "requiere evidencia":
            self.requiere_evidencia = True
        self.detalles = redactar_secretos(self.detalles)
        self.evidencia = redactar_secretos(self.evidencia)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def registrar_bitacora(
    resultado: ResultadoVerificacion,
    usuario: str = "analista",
    autorizacion_confirmada: bool = True
) -> None:
    """Registra de forma segura la ejecución de cada prueba en la bitácora JSONL."""
    entrada = {
        "timestamp": resultado.timestamp,
        "usuario": usuario,
        "autorizacion_confirmada": bool(autorizacion_confirmada),
        "modo": resultado.modo,
        "objetivo": redactar_secretos(resultado.objetivo),
        "control_id": resultado.control_id,
        "control_nombre": resultado.nombre,
        "estado": resultado.estado,
        "duracion_ms": resultado.duracion_ms,
        "detalles": resultado.detalles,
    }
    try:
        BITACORA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _bitacora_lock:
            with open(BITACORA_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
    except OSError:
        pass


def leer_bitacora(limit: int = 50) -> List[Dict[str, Any]]:
    """Lee las últimas entradas de la bitácora de verificaciones en orden cronológico inverso."""
    try:
        with open(BITACORA_FILE, "r", encoding="utf-8") as f:
            lineas = f.readlines()
    except OSError:
        return []
    entradas: List[Dict[str, Any]] = []
    for linea in reversed(lineas):
        try:
            entradas.append(json.loads(linea))
        except json.JSONDecodeError:
            continue
        if len(entradas) >= max(1, min(limit, 200)):
            break
    return entradas
