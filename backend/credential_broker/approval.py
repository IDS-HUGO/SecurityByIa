"""Sistema de Aprobación Humana para Credential Broker (F12).

Gestiona las solicitudes de acceso solicitadas por agentes hacia sitios privados,
asegurando que ningún agente pueda autenticarse sin la debida autorización humana
según lo exija la política del sitio.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

APPROVAL_STORAGE_FILE = Path(__file__).resolve().parents[1] / "storage" / "credentials" / "approvals.json"


@dataclass
class ApprovalRequest:
    request_id: str
    site_id: str
    target_origin: str
    agent_id: str
    task_purpose: str
    requested_ttl_seconds: int = 1800
    status: str = "pending"  # "pending", "approved", "rejected", "revoked", "expired"
    requested_at: str = ""
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: str = ""
    expires_at: Optional[float] = None

    def __post_init__(self):
        if not self.requested_at:
            self.requested_at = datetime.now(timezone.utc).isoformat()

    def is_valid(self) -> bool:
        """Comprueba si la aprobación está concedida y dentro de su ventana de tiempo."""
        if self.status != "approved":
            return False
        if self.expires_at and time.time() > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApprovalManager:
    """Administrador persistente de solicitudes de aprobación de credenciales."""

    def __init__(self, storage_file: Optional[Path] = None):
        self.storage_file = storage_file or APPROVAL_STORAGE_FILE
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        self._requests: Dict[str, ApprovalRequest] = {}
        self._load()

    def _load(self) -> None:
        if not self.storage_file.exists():
            return
        try:
            with open(self.storage_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for req_id, row in data.items():
                self._requests[req_id] = ApprovalRequest(**row)
        except Exception:
            self._requests = {}

    def _persist(self) -> None:
        try:
            payload = {k: v.to_dict() for k, v in self._requests.items()}
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except OSError:
            pass

    def request_access(self, site_id: str, target_origin: str, agent_id: str,
                       task_purpose: str, requested_ttl: int = 1800) -> ApprovalRequest:
        """Crea una nueva solicitud de acceso pendiente de autorización humana."""
        token_src = f"{site_id}:{agent_id}:{time.time()}:{os.urandom(8).hex()}"
        req_id = f"apr_{hashlib.sha256(token_src.encode('utf-8')).hexdigest()[:16]}"
        
        req = ApprovalRequest(
            request_id=req_id,
            site_id=site_id,
            target_origin=target_origin,
            agent_id=agent_id,
            task_purpose=task_purpose,
            requested_ttl_seconds=requested_ttl,
            status="pending",
        )
        self._requests[req_id] = req
        self._persist()
        return req

    def approve(self, request_id: str, reviewer: str, reason: str = "Aprobado por analista",
                granted_ttl: Optional[int] = None) -> bool:
        """Aprueba una solicitud pendiente."""
        req = self._requests.get(request_id)
        if not req or req.status != "pending":
            return False

        ttl = granted_ttl or req.requested_ttl_seconds
        req.status = "approved"
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = reviewer
        req.decision_reason = reason
        req.expires_at = time.time() + ttl
        self._persist()
        return True

    def reject(self, request_id: str, reviewer: str, reason: str = "Rechazado por analista") -> bool:
        """Rechaza una solicitud de credenciales."""
        req = self._requests.get(request_id)
        if not req:
            return False
        req.status = "rejected"
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = reviewer
        req.decision_reason = reason
        self._persist()
        return True

    def revoke(self, request_id: str, revoker: str, reason: str = "Revocación inmediata") -> bool:
        """Revoca inmediatamente un acceso previamente concedido."""
        req = self._requests.get(request_id)
        if not req:
            return False
        req.status = "revoked"
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = revoker
        req.decision_reason = reason
        self._persist()
        return True

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        req = self._requests.get(request_id)
        if req and req.status == "approved" and req.expires_at and time.time() > req.expires_at:
            req.status = "expired"
            self._persist()
        return req

    def list_requests(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        now = time.time()
        res = []
        for req in self._requests.values():
            if req.status == "approved" and req.expires_at and now > req.expires_at:
                req.status = "expired"
            if not status or req.status == status:
                res.append(req.to_dict())
        return sorted(res, key=lambda x: x.get("requested_at", ""), reverse=True)
