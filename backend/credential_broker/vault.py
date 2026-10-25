"""Adaptadores de Bóvedas de Credenciales para Credential Broker (F12).

Proporciona una interfaz unificada para acceder a secretos web (usuario, password, TOTP)
garantizando que ninguna credencial viaje al contexto de un agente o modelo de IA.
"""

from abc import ABC, abstractmethod
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Dict, List, Optional

VAULT_STORAGE_DIR = Path(__file__).resolve().parents[1] / "storage" / "credentials"


class BaseVault(ABC):
    """Interfaz abstracta para almacenes de credenciales."""

    @abstractmethod
    def store_credential(self, ref: str, username: str, password: str,
                         totp_seed: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Almacena una credencial (solo invocable por administradores o setup)."""
        pass

    @abstractmethod
    def get_credential(self, ref: str) -> Optional[Dict[str, Any]]:
        """Obtiene credenciales. SOLO para uso interno del Broker de Confianza."""
        pass

    @abstractmethod
    def list_refs(self) -> List[Dict[str, Any]]:
        """Lista las referencias guardadas sin revelar contraseñas ni semillas."""
        pass

    @abstractmethod
    def delete_credential(self, ref: str) -> bool:
        """Elimina una credencial."""
        pass


class FakeVault(BaseVault):
    """Bóveda en memoria para pruebas unitarias y entornos de desarrollo."""

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}

    def store_credential(self, ref: str, username: str, password: str,
                         totp_seed: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._data[ref] = {
            "ref": ref,
            "username": username,
            "password": password,
            "totp_seed": totp_seed,
            "metadata": metadata or {},
        }

    def get_credential(self, ref: str) -> Optional[Dict[str, Any]]:
        val = self._data.get(ref)
        if not val:
            return None
        # Retorna copia para uso del worker de confianza
        return dict(val)

    def list_refs(self) -> List[Dict[str, Any]]:
        return [
            {
                "ref": item["ref"],
                "username": item["username"],
                "has_totp": bool(item.get("totp_seed")),
                "metadata": item.get("metadata", {}),
            }
            for item in self._data.values()
        ]

    def delete_credential(self, ref: str) -> bool:
        if ref in self._data:
            del self._data[ref]
            return True
        return False


class EncryptedFileVault(BaseVault):
    """Almacén cifrado en disco local con permisos restrictivos (0600)."""

    def __init__(self, storage_dir: Optional[Path] = None, secret_key: Optional[str] = None):
        self.storage_dir = storage_dir or VAULT_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file = self.storage_dir / "vault.enc"
        
        # Derivar clave de cifrado simétrico
        raw_key = secret_key or os.environ.get("CREDENTIAL_BROKER_KEY", "neurotry-default-dev-vault-key-2026")
        self._cipher_key = hashlib.sha256(raw_key.encode("utf-8")).digest()
        self._ensure_file_permissions()

    def _ensure_file_permissions(self) -> None:
        if self.vault_file.exists():
            try:
                os.chmod(self.vault_file, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except OSError:
                pass

    def _encrypt(self, data: Dict[str, Any]) -> bytes:
        raw_bytes = json.dumps(data).encode("utf-8")
        # Encriptación simétrica simple XOR-stream con digest HMAC/SHA256 para evitar dependencias obligatorias
        keystream = hashlib.sha256(self._cipher_key + b":keystream").digest()
        expanded_key = (keystream * ((len(raw_bytes) // len(keystream)) + 1))[:len(raw_bytes)]
        cipher = bytes(b ^ k for b, k in zip(raw_bytes, expanded_key))
        mac = hashlib.sha256(self._cipher_key + cipher).digest()
        return mac + cipher

    def _decrypt(self, payload: bytes) -> Dict[str, Any]:
        if len(payload) < 32:
            return {}
        mac = payload[:32]
        cipher = payload[32:]
        expected_mac = hashlib.sha256(self._cipher_key + cipher).digest()
        if mac != expected_mac:
            raise ValueError("Integridad del archivo de bóveda comprometida o clave incorrecta")
        
        keystream = hashlib.sha256(self._cipher_key + b":keystream").digest()
        expanded_key = (keystream * ((len(cipher) // len(keystream)) + 1))[:len(cipher)]
        raw_bytes = bytes(c ^ k for c, k in zip(cipher, expanded_key))
        return json.loads(raw_bytes.decode("utf-8"))

    def _load_data(self) -> Dict[str, Any]:
        if not self.vault_file.exists():
            return {}
        try:
            with open(self.vault_file, "rb") as f:
                content = f.read()
            if not content:
                return {}
            return self._decrypt(content)
        except Exception:
            return {}

    def _save_data(self, data: Dict[str, Any]) -> None:
        payload = self._encrypt(data)
        with open(self.vault_file, "wb") as f:
            f.write(payload)
        self._ensure_file_permissions()

    def store_credential(self, ref: str, username: str, password: str,
                         totp_seed: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        data = self._load_data()
        data[ref] = {
            "ref": ref,
            "username": username,
            "password": password,
            "totp_seed": totp_seed,
            "metadata": metadata or {},
        }
        self._save_data(data)

    def get_credential(self, ref: str) -> Optional[Dict[str, Any]]:
        data = self._load_data()
        item = data.get(ref)
        if not item:
            return None
        return dict(item)

    def list_refs(self) -> List[Dict[str, Any]]:
        data = self._load_data()
        return [
            {
                "ref": item["ref"],
                "username": item["username"],
                "has_totp": bool(item.get("totp_seed")),
                "metadata": item.get("metadata", {}),
            }
            for item in data.values()
        ]

    def delete_credential(self, ref: str) -> bool:
        data = self._load_data()
        if ref in data:
            del data[ref]
            self._save_data(data)
            return True
        return False


class BitwardenCliVault(BaseVault):
    """Adaptador para Bitwarden CLI (bw) en producción."""

    def __init__(self, session_key: Optional[str] = None):
        self.session_key = session_key or os.environ.get("BW_SESSION")

    def is_available(self) -> bool:
        return bool(self.session_key)

    def store_credential(self, ref: str, username: str, password: str,
                         totp_seed: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        raise NotImplementedError("La creación de credenciales en Bitwarden debe realizarse desde el gestor corporativo")

    def get_credential(self, ref: str) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None
        try:
            env = os.environ.copy()
            env["BW_SESSION"] = self.session_key
            result = subprocess.run(
                ["bw", "get", "item", ref],
                capture_output=True, text=True, check=True, env=env, timeout=10
            )
            data = json.loads(result.stdout)
            login = data.get("login", {})
            return {
                "ref": ref,
                "username": login.get("username", ""),
                "password": login.get("password", ""),
                "totp_seed": login.get("totp", None),
                "metadata": {"name": data.get("name")},
            }
        except Exception:
            return None

    def list_refs(self) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []
        try:
            env = os.environ.copy()
            env["BW_SESSION"] = self.session_key
            result = subprocess.run(
                ["bw", "list", "items"],
                capture_output=True, text=True, check=True, env=env, timeout=10
            )
            items = json.loads(result.stdout)
            return [
                {
                    "ref": it.get("id"),
                    "username": it.get("login", {}).get("username", ""),
                    "has_totp": bool(it.get("login", {}).get("totp")),
                    "metadata": {"name": it.get("name")},
                }
                for it in items
            ]
        except Exception:
            return []

    def delete_credential(self, ref: str) -> bool:
        raise NotImplementedError("Eliminación restringida")


class OnePasswordCliVault(BaseVault):
    """Adaptador para 1Password CLI (op) en producción."""

    def __init__(self, service_account_token: Optional[str] = None):
        self.token = service_account_token or os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")

    def is_available(self) -> bool:
        return bool(self.token)

    def store_credential(self, ref: str, username: str, password: str,
                         totp_seed: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        raise NotImplementedError("La creación de credenciales en 1Password debe realizarse desde el gestor corporativo")

    def get_credential(self, ref: str) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None
        try:
            env = os.environ.copy()
            env["OP_SERVICE_ACCOUNT_TOKEN"] = self.token
            result = subprocess.run(
                ["op", "item", "get", ref, "--format", "json"],
                capture_output=True, text=True, check=True, env=env, timeout=10
            )
            data = json.loads(result.stdout)
            username = ""
            password = ""
            totp = None
            for f in data.get("fields", []):
                if f.get("id") == "username":
                    username = f.get("value", "")
                elif f.get("id") == "password":
                    password = f.get("value", "")
                elif f.get("type") == "OTP":
                    totp = f.get("value", "")
            return {
                "ref": ref,
                "username": username,
                "password": password,
                "totp_seed": totp,
                "metadata": {"title": data.get("title")},
            }
        except Exception:
            return None

    def list_refs(self) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []
        try:
            env = os.environ.copy()
            env["OP_SERVICE_ACCOUNT_TOKEN"] = self.token
            result = subprocess.run(
                ["op", "item", "list", "--format", "json"],
                capture_output=True, text=True, check=True, env=env, timeout=10
            )
            items = json.loads(result.stdout)
            return [
                {
                    "ref": it.get("id"),
                    "username": "",
                    "has_totp": False,
                    "metadata": {"title": it.get("title")},
                }
                for it in items
            ]
        except Exception:
            return []

    def delete_credential(self, ref: str) -> bool:
        raise NotImplementedError("Eliminación restringida")
