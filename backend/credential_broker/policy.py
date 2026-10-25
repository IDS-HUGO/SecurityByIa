"""Módulo de Gestión de Políticas para Credential Broker (F12).

Administra dominios permitidos, TTLs, acciones prohibidas y requisitos
de aprobación humana para el acceso de agentes a sitios web protegidos.
"""

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse
import yaml

DEFAULT_POLICY_FILE = Path(__file__).resolve().parents[1] / "data" / "credentials-policy.yml"


@dataclass
class SitePolicy:
    site_id: str
    allowed_origin: str
    vault_ref: str
    require_approval: str = "always"  # "always", "once", "none"
    max_ttl_seconds: int = 1800
    forbidden_actions: List[str] = field(default_factory=lambda: [
        "/admin/change-password",
        "/account/delete",
        "/billing",
        "/checkout",
        "/users/delete"
    ])
    owner: str = "seguridad@neurotry.local"
    description: str = ""

    def validate_origin(self, target_url: str) -> bool:
        """Verifica que el target_url coincida exactamente con el origen permitido."""
        if not target_url:
            return False
        parsed_target = urllib.parse.urlparse(target_url)
        parsed_allowed = urllib.parse.urlparse(self.allowed_origin)

        # Esquema (http/https) y netloc (host:puerto) deben coincidir
        if parsed_target.scheme.lower() != parsed_allowed.scheme.lower():
            return False
        if parsed_target.netloc.lower() != parsed_allowed.netloc.lower():
            return False
        return True

    def is_action_allowed(self, target_path: str) -> bool:
        """Verifica si la ruta solicitada no se encuentra entre las prohibidas."""
        normalized = target_path.lower()
        for forbidden in self.forbidden_actions:
            if forbidden.lower() in normalized:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    """Motor de carga y validación de políticas de acceso a credenciales."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy_path = policy_path or DEFAULT_POLICY_FILE
        self._policies: Dict[str, SitePolicy] = {}
        self.reload()

    def reload(self) -> None:
        """Carga o recarga las políticas desde el archivo YAML."""
        self._policies.clear()
        if not self.policy_path.exists():
            # Crear políticas por defecto de muestra
            self._create_default_policy_file()

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            sites = data.get("sites", {})
            for site_id, cfg in sites.items():
                self._policies[site_id] = SitePolicy(
                    site_id=site_id,
                    allowed_origin=cfg.get("allowed_origin", ""),
                    vault_ref=cfg.get("vault_ref", site_id),
                    require_approval=cfg.get("require_approval", "always"),
                    max_ttl_seconds=int(cfg.get("max_ttl_seconds", 1800)),
                    forbidden_actions=cfg.get("forbidden_actions", []),
                    owner=cfg.get("owner", "seguridad@neurotry.local"),
                    description=cfg.get("description", ""),
                )
        except Exception:
            # En caso de error, mantener diccionario vacío o fallback seguro
            pass

    def get_policy(self, site_id: str) -> Optional[SitePolicy]:
        return self._policies.get(site_id)

    def list_policies(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._policies.values()]

    def register_policy(self, policy: SitePolicy) -> None:
        self._policies[policy.site_id] = policy
        self._persist()

    def _persist(self) -> None:
        """Guarda la configuración actual en el YAML de políticas."""
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "sites": {p.site_id: p.to_dict() for p in self._policies.values()}
        }
        with open(self.policy_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, indent=2, sort_keys=False)

    def _create_default_policy_file(self) -> None:
        """Crea plantilla por defecto si no existe."""
        defaults = {
            "version": "1.0",
            "sites": {
                "local-test-app": {
                    "allowed_origin": "http://127.0.0.1:5050",
                    "vault_ref": "local-test-app",
                    "require_approval": "always",
                    "max_ttl_seconds": 1800,
                    "forbidden_actions": ["/admin/delete", "/users/revoke"],
                    "owner": "qa@neurotry.local",
                    "description": "Aplicación web local para pruebas de autenticación",
                }
            }
        }
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.policy_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(defaults, f, indent=2)
        except OSError:
            pass
