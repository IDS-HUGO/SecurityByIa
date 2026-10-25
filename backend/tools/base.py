"""Especificación común y clase base para herramientas de seguridad (F14).

Define una interfaz homogénea para herramientas de cualquier categoría
(SAST, SCA, Secretos, IaC, CI, Contenedor, Licencia, SBOM, Reputación)
permitiendo un registro extensible en lugar de cadenas de condicionales.
"""

from abc import ABC, abstractmethod
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple


class BaseTool(ABC):
    """Clase base abstracta para toda herramienta de escaneo."""

    id: str = "base"
    name: str = "Base Tool"
    category: str = "sast"  # sast, sca, secrets, iac, ci, container, license, sbom, reputation
    languages: List[str] = ["all"]
    binary_name: str = ""
    env_var: str = ""
    default_timeout: int = 180
    works_offline: bool = True
    install_hint: str = ""

    def get_binary_path(self) -> Optional[str]:
        """Localiza el binario: variable de entorno primero, luego en el PATH."""
        if self.env_var:
            custom = os.environ.get(self.env_var)
            if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
                return custom
        if self.binary_name:
            return shutil.which(self.binary_name)
        return None

    def is_available(self) -> bool:
        """Determina si la herramienta está instalada y ejecutable en el sistema."""
        return self.get_binary_path() is not None

    def get_version(self) -> str:
        """Obtiene la versión instalada ejecutando el comando correspondiente."""
        bin_path = self.get_binary_path()
        if not bin_path:
            return "no instalada"
        try:
            res = subprocess.run(
                [bin_path, "--version"],
                capture_output=True, text=True, timeout=5, check=False
            )
            out = (res.stdout or res.stderr or "").strip().split("\n")[0]
            return out[:50] if out else "instalada"
        except Exception:
            return "instalada"

    @abstractmethod
    def applies_to(self, stack: Dict[str, Any]) -> bool:
        """Evalúa si la herramienta aplica al stack detectado en el repositorio."""
        pass

    @abstractmethod
    def run(
        self,
        root: str,
        stack: Dict[str, Any],
        timeout: int = 180,
        extra_args: Optional[Dict[str, Any]] = None
    ) -> Tuple[Any, str]:
        """Ejecuta el análisis y retorna (hallazgos_o_reporte, estado).
        
        Estados posibles: 'completed', 'unavailable', 'skipped', 'error', 'degraded'.
        """
        pass
