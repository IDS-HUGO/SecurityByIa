"""Módulo Credential Broker (F12) - Acceso Web Delegado para Agentes.

Permite a los agentes interactuar con sitios web autenticados sin conocer jamás
las contraseñas, semillas TOTP ni secretos.
"""

from credential_broker.policy import SitePolicy, PolicyEngine
from credential_broker.vault import BaseVault, FakeVault, EncryptedFileVault
from credential_broker.approval import ApprovalManager, ApprovalRequest
from credential_broker.worker import (
    BrowserAuthWorker,
    generate_totp_code,
    sanitize_view_for_agent,
    OriginMismatchError,
    UnauthorizedApprovalError,
    CrossDomainIframeError,
    CredentialBrokerError,
)
from credential_broker.audit import log_broker_audit, read_broker_audit
from credential_broker.broker import CredentialBroker, get_credential_broker

__all__ = [
    "CredentialBroker",
    "get_credential_broker",
    "SitePolicy",
    "PolicyEngine",
    "BaseVault",
    "FakeVault",
    "EncryptedFileVault",
    "ApprovalManager",
    "ApprovalRequest",
    "BrowserAuthWorker",
    "generate_totp_code",
    "sanitize_view_for_agent",
    "OriginMismatchError",
    "UnauthorizedApprovalError",
    "CrossDomainIframeError",
    "CredentialBrokerError",
    "log_broker_audit",
    "read_broker_audit",
]
