"""Fachada principal del Credential Broker (F12).

Orquesta las políticas de acceso, adaptadores de bóveda, flujo de aprobación humana,
workers de autenticación segura y auditoría inmutable.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from credential_broker.policy import PolicyEngine, SitePolicy
from credential_broker.vault import BaseVault, EncryptedFileVault, FakeVault
from credential_broker.approval import ApprovalManager, ApprovalRequest
from credential_broker.worker import BrowserAuthWorker, sanitize_view_for_agent
from credential_broker.audit import log_broker_audit, read_broker_audit


class CredentialBroker:
    """Instancia central del broker de credenciales para agentes."""

    def __init__(
        self,
        vault: Optional[BaseVault] = None,
        policy_engine: Optional[PolicyEngine] = None,
        approval_manager: Optional[ApprovalManager] = None,
        storage_dir: Optional[Path] = None,
    ):
        self.storage_dir = storage_dir or (Path(__file__).resolve().parents[1] / "storage" / "credentials")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.vault = vault or EncryptedFileVault(storage_dir=self.storage_dir)
        self.policy_engine = policy_engine or PolicyEngine(policy_path=self.storage_dir / "credentials-policy.yml")
        self.approval_manager = approval_manager or ApprovalManager(storage_file=self.storage_dir / "approvals.json")
        self.worker = BrowserAuthWorker(vault=self.vault, storage_dir=self.storage_dir / "sessions")

    def register_site(
        self,
        site_id: str,
        allowed_origin: str,
        username: str,
        password: str,
        totp_seed: Optional[str] = None,
        require_approval: str = "always",
        max_ttl_seconds: int = 1800,
        owner: str = "analista@neurotry.local",
        description: str = "",
        forbidden_actions: Optional[List[str]] = None,
    ) -> None:
        """Registra un sitio con su política y almacena sus credenciales en la bóveda de forma segura.
        
        Solo invocable por operadores humanos o configuraciones administrativas.
        """
        vault_ref = f"vault_ref_{site_id}"
        self.vault.store_credential(
            ref=vault_ref,
            username=username,
            password=password,
            totp_seed=totp_seed,
            metadata={"site_id": site_id, "owner": owner}
        )

        policy = SitePolicy(
            site_id=site_id,
            allowed_origin=allowed_origin,
            vault_ref=vault_ref,
            require_approval=require_approval,
            max_ttl_seconds=max_ttl_seconds,
            forbidden_actions=forbidden_actions or ["/admin/change-password", "/account/delete", "/billing"],
            owner=owner,
            description=description,
        )
        self.policy_engine.register_policy(policy)
        log_broker_audit("site_registered", site_id, "admin", "success", {"origin": allowed_origin})

    def request_access(
        self,
        site_id: str,
        agent_id: str,
        task_purpose: str,
        requested_ttl: int = 1800
    ) -> Dict[str, Any]:
        """El agente solicita acceso para realizar una tarea sobre un sitio.
        
        Si la política exige aprobación humana ('always' o 'once'), genera una solicitud pendiente.
        Si la política es 'none', aprueba automáticamente.
        """
        policy = self.policy_engine.get_policy(site_id)
        if not policy:
            raise ValueError(f"El sitio '{site_id}' no está registrado en las políticas del broker.")

        req = self.approval_manager.request_access(
            site_id=site_id,
            target_origin=policy.allowed_origin,
            agent_id=agent_id,
            task_purpose=task_purpose,
            requested_ttl=min(requested_ttl, policy.max_ttl_seconds)
        )

        if policy.require_approval == "none":
            self.approval_manager.approve(req.request_id, reviewer="policy_auto_none", reason="Auto-aprobado por política")

        log_broker_audit("approval_requested", site_id, agent_id, req.status,
                         {"request_id": req.request_id, "purpose": task_purpose})

        return req.to_dict()

    def approve_request(
        self,
        request_id: str,
        reviewer: str,
        reason: str = "Aprobado por analista",
        granted_ttl: Optional[int] = None
    ) -> bool:
        """Aprueba humanamente una solicitud pendiente."""
        success = self.approval_manager.approve(request_id, reviewer=reviewer, reason=reason, granted_ttl=granted_ttl)
        req = self.approval_manager.get_request(request_id)
        if req:
            log_broker_audit("approval_decided", req.site_id, req.agent_id, "approved",
                             {"request_id": request_id, "reviewer": reviewer, "reason": reason})
        return success

    def reject_request(
        self,
        request_id: str,
        reviewer: str,
        reason: str = "Rechazado por analista"
    ) -> bool:
        """Rechaza una solicitud de credenciales."""
        success = self.approval_manager.reject(request_id, reviewer=reviewer, reason=reason)
        req = self.approval_manager.get_request(request_id)
        if req:
            log_broker_audit("approval_decided", req.site_id, req.agent_id, "rejected",
                             {"request_id": request_id, "reviewer": reviewer, "reason": reason})
        return success

    def execute_login(
        self,
        site_id: str,
        target_url: str,
        agent_id: str,
        request_id: Optional[str] = None,
        custom_executor: Optional[Callable[..., Dict[str, Any]]] = None,
        iframe_origin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ejecuta el login protegido mediante el worker de confianza.
        
        Valida política, origen, iframes y estado de aprobación humana.
        """
        policy = self.policy_engine.get_policy(site_id)
        if not policy:
            raise ValueError(f"Sitio '{site_id}' no encontrado en políticas.")

        is_approved = False
        if policy.require_approval == "none":
            is_approved = True
        elif request_id:
            req = self.approval_manager.get_request(request_id)
            if req and req.is_valid():
                is_approved = True

        result = self.worker.execute_login(
            policy=policy,
            target_url=target_url,
            agent_id=agent_id,
            is_approval_valid=is_approved,
            executor_fn=custom_executor,
            iframe_origin=iframe_origin,
        )

        return result

    def revoke_session(self, session_id: str) -> bool:
        """Revoca de forma inmediata una sesión delegada."""
        return self.worker.revoke_session(session_id)

    def list_sites(self) -> List[Dict[str, Any]]:
        """Lista los sitios registrados y sus políticas (sin contraseñas)."""
        sites = self.policy_engine.list_policies()
        vault_refs = {item["ref"]: item for item in self.vault.list_refs()}
        for s in sites:
            vref = s.get("vault_ref")
            s["has_credentials"] = vref in vault_refs
            s["username"] = vault_refs.get(vref, {}).get("username", "")
            s["has_totp"] = vault_refs.get(vref, {}).get("has_totp", False)
        return sites

    def list_approvals(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.approval_manager.list_requests(status=status)

    def list_active_sessions(self) -> List[Dict[str, Any]]:
        """Lista las sesiones delegadas actualmente activas."""
        sessions_dir = self.storage_dir / "sessions"
        if not sessions_dir.exists():
            return []
        active = []
        for p in sessions_dir.glob("*.json"):
            sess = self.worker.get_session(p.stem)
            if sess:
                active.append({
                    "session_id": sess.get("session_id"),
                    "site_id": sess.get("site_id"),
                    "agent_id": sess.get("agent_id"),
                    "created_at": sess.get("created_at"),
                    "expires_at": sess.get("expires_at"),
                    "allowed_origin": sess.get("allowed_origin"),
                })
        return active

    def get_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        return read_broker_audit(limit=limit)


# Instancia singleton predeterminada
_default_broker: Optional[CredentialBroker] = None


def get_credential_broker() -> CredentialBroker:
    global _default_broker
    if _default_broker is None:
        _default_broker = CredentialBroker()
    return _default_broker
