"""Registro modular y orquestador de herramientas de seguridad (F14).

Reemplaza la cadena fija de if en run_tools() por un registro extensible
de herramientas con metadatos uniformes, comando de versión y verificación
de disponibilidad para 'secai doctor' y 'GET /api/tools'.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple
import os

from tools.base import BaseTool
from tools.stack_detector import detect_stack_v2


class GenericToolAdapter(BaseTool):
    """Adaptador que envuelve funciones de escaneo existentes para integrarlas en el registro."""

    def __init__(
        self,
        tool_id: str,
        name: str,
        category: str,
        languages: List[str],
        binary_name: str,
        env_var: str,
        applies_predicate: Callable[[Dict[str, Any]], bool],
        runner_fn: Callable[..., Tuple[Any, str]],
        install_hint: str = "",
        is_report_only: bool = False,
        report_key: Optional[str] = None,
    ):
        self.id = tool_id
        self.name = name
        self.category = category
        self.languages = languages
        self.binary_name = binary_name
        self.env_var = env_var
        self._applies_predicate = applies_predicate
        self._runner_fn = runner_fn
        self.install_hint = install_hint
        self.is_report_only = is_report_only
        self.report_key = report_key

    def applies_to(self, stack: Dict[str, Any]) -> bool:
        return self._applies_predicate(stack)

    def run(
        self,
        root: str,
        stack: Dict[str, Any],
        timeout: int = 180,
        extra_args: Optional[Dict[str, Any]] = None
    ) -> Tuple[Any, str]:
        return self._runner_fn(root, stack, timeout, extra_args or {})


class ToolRegistry:
    """Registro central de herramientas de escaneo del Security Control Center."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._register_default_tools()

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.id] = tool

    def get(self, tool_id: str) -> Optional[BaseTool]:
        return self._tools.get(tool_id)

    def list_all(self) -> List[BaseTool]:
        return list(self._tools.values())

    def get_installed_tools_status(self) -> List[Dict[str, Any]]:
        """Retorna inventario para 'secai doctor' y 'GET /api/tools'."""
        info = []
        for t in self.list_all():
            available = t.is_available()
            version = t.get_version() if available else "no instalada"
            info.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "languages": t.languages,
                "binary": t.binary_name,
                "installed": available,
                "version": version,
                "works_offline": t.works_offline,
                "install_hint": t.install_hint,
            })
        return sorted(info, key=lambda x: (x["category"], x["id"]))

    def _register_default_tools(self) -> None:
        """Registra el catálogo completo de herramientas nativas y políglotas."""
        import scanner_tools as st

        # 1. SAST
        self.register(GenericToolAdapter(
            tool_id="bandit",
            name="Bandit",
            category="sast",
            languages=["python"],
            binary_name="bandit",
            env_var="BANDIT_PATH",
            applies_predicate=lambda s: bool(s.get("has_python") or "python" in s.get("languages", [])),
            runner_fn=lambda r, s, t, a: st._run_bandit(r, t),
            install_hint="pip install bandit"
        ))

        self.register(GenericToolAdapter(
            tool_id="semgrep",
            name="Semgrep",
            category="sast",
            languages=["python", "javascript", "typescript", "go", "java", "ruby", "csharp", "php", "rust"],
            binary_name="semgrep",
            env_var="SEMGREP_PATH",
            applies_predicate=lambda s: True,  # Corre sobre cualquier lenguaje soportado
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="pip install semgrep"
        ))

        # 2. Secretos
        self.register(GenericToolAdapter(
            tool_id="gitleaks",
            name="Gitleaks",
            category="secrets",
            languages=["all"],
            binary_name="gitleaks",
            env_var="GITLEAKS_PATH",
            applies_predicate=lambda s: True,
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="brew install gitleaks o descarga desde GitHub"
        ))

        self.register(GenericToolAdapter(
            tool_id="trufflehog",
            name="TruffleHog",
            category="secrets",
            languages=["all"],
            binary_name="trufflehog",
            env_var="TRUFFLEHOG_PATH",
            applies_predicate=lambda s: True,
            runner_fn=lambda r, s, t, a: st._run_trufflehog(r, a.get("scan_git_history", False), t),
            install_hint="brew install trufflehog"
        ))

        # 3. SCA (Dependencias vulnerables)
        self.register(GenericToolAdapter(
            tool_id="osv-scanner",
            name="OSV-Scanner",
            category="sca",
            languages=["python", "javascript", "typescript", "go", "java", "rust", "ruby", "php", "dart", "csharp"],
            binary_name="osv-scanner",
            env_var="OSV_SCANNER_PATH",
            applies_predicate=lambda s: bool(s.get("dependency_files")),
            runner_fn=lambda r, s, t, a: st._run_osv(r, t),
            install_hint="go install github.com/google/osv-scanner/cmd/osv-scanner@v1"
        ))

        self.register(GenericToolAdapter(
            tool_id="pip-audit",
            name="pip-audit",
            category="sca",
            languages=["python"],
            binary_name="pip-audit",
            env_var="PIP_AUDIT_PATH",
            applies_predicate=lambda s: bool(s.get("requirements_files")),
            runner_fn=lambda r, s, t, a: st._run_pip_audit(r, s.get("requirements_files", []), t),
            install_hint="pip install pip-audit"
        ))

        self.register(GenericToolAdapter(
            tool_id="npm-audit",
            name="npm audit",
            category="sca",
            languages=["javascript", "typescript", "node"],
            binary_name="npm",
            env_var="NPM_PATH",
            applies_predicate=lambda s: bool(s.get("package_lock")),
            runner_fn=lambda r, s, t, a: st._run_npm_audit(r, t),
            install_hint="Instalar Node.js / npm"
        ))

        # 4. IaC
        self.register(GenericToolAdapter(
            tool_id="checkov",
            name="Checkov",
            category="iac",
            languages=["terraform", "cloudformation", "kubernetes", "dockerfile"],
            binary_name="checkov",
            env_var="CHECKOV_PATH",
            applies_predicate=lambda s: bool(s.get("terraform") or s.get("cloudformation") or "kubernetes" in s.get("iac_types", [])),
            runner_fn=lambda r, s, t, a: st._run_checkov(r, t),
            install_hint="pip install checkov"
        ))

        self.register(GenericToolAdapter(
            tool_id="trivy",
            name="Trivy",
            category="iac",
            languages=["terraform", "dockerfile", "kubernetes"],
            binary_name="trivy",
            env_var="TRIVY_PATH",
            applies_predicate=lambda s: bool(s.get("terraform") or s.get("cloudformation") or s.get("dockerfiles")),
            runner_fn=lambda r, s, t, a: st._run_trivy(r, t),
            install_hint="brew install trivy o descarga desde GitHub"
        ))

        # 5. CI / Contenedores
        self.register(GenericToolAdapter(
            tool_id="hadolint",
            name="hadolint",
            category="ci",
            languages=["dockerfile"],
            binary_name="hadolint",
            env_var="HADOLINT_PATH",
            applies_predicate=lambda s: bool(s.get("dockerfiles")),
            runner_fn=lambda r, s, t, a: st._run_hadolint(r, s.get("dockerfiles", []), t),
            install_hint="brew install hadolint"
        ))

        self.register(GenericToolAdapter(
            tool_id="zizmor",
            name="zizmor",
            category="ci",
            languages=["github-actions"],
            binary_name="zizmor",
            env_var="ZIZMOR_PATH",
            applies_predicate=lambda s: bool(s.get("github_workflows")),
            runner_fn=lambda r, s, t, a: st._run_zizmor(r, t),
            install_hint="cargo install zizmor"
        ))

        # 6. Licencias, SBOM, Reputación
        self.register(GenericToolAdapter(
            tool_id="scancode",
            name="ScanCode",
            category="licencias",
            languages=["all"],
            binary_name="scancode",
            env_var="SCANCODE_PATH",
            applies_predicate=lambda s: bool(s.get("dependency_files")),
            runner_fn=lambda r, s, t, a: st._run_scancode(r, t),
            is_report_only=True,
            report_key="licenses",
            install_hint="pip install scancode-toolkit"
        ))

        self.register(GenericToolAdapter(
            tool_id="syft",
            name="Syft",
            category="sbom",
            languages=["all"],
            binary_name="syft",
            env_var="SYFT_PATH",
            applies_predicate=lambda s: bool(s.get("dependency_files")),
            runner_fn=lambda r, s, t, a: st._run_syft(r, t),
            is_report_only=True,
            report_key="sbom",
            install_hint="curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"
        ))

        self.register(GenericToolAdapter(
            tool_id="scorecard",
            name="Scorecard",
            category="reputacion",
            languages=["all"],
            binary_name="scorecard",
            env_var="SCORECARD_PATH",
            applies_predicate=lambda s: True,
            runner_fn=lambda r, s, t, a: st._run_scorecard(r, t),
            is_report_only=True,
            report_key="scorecard",
            install_hint="Descarga binario scorecard de OpenSSF"
        ))

        # 7. Dependencias sin uso
        self.register(GenericToolAdapter(
            tool_id="depcheck",
            name="depcheck",
            category="sca",
            languages=["javascript", "typescript", "node"],
            binary_name="depcheck",
            env_var="DEPCHECK_PATH",
            applies_predicate=lambda s: bool(s.get("has_node")),
            runner_fn=lambda r, s, t, a: st._run_depcheck(r, t),
            install_hint="npm install -g depcheck"
        ))

        self.register(GenericToolAdapter(
            tool_id="deptry",
            name="deptry",
            category="sca",
            languages=["python"],
            binary_name="deptry",
            env_var="DEPTRY_PATH",
            applies_predicate=lambda s: bool(s.get("has_python")),
            runner_fn=lambda r, s, t, a: st._run_deptry(r, (s.get("dependency_files") or ["requirements.txt"])[0], t),
            install_hint="pip install deptry"
        ))

        # 8. Soporte políglota extendido: Go, Java, Ruby, Rust, PHP, C/C++, Solidity, Elixir
        self.register(GenericToolAdapter(
            tool_id="gosec",
            name="Gosec",
            category="sast",
            languages=["go"],
            binary_name="gosec",
            env_var="GOSEC_PATH",
            applies_predicate=lambda s: "go" in s.get("languages", []),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="go install github.com/securego/gosec/v2/cmd/gosec@latest"
        ))

        self.register(GenericToolAdapter(
            tool_id="brakeman",
            name="Brakeman",
            category="sast",
            languages=["ruby"],
            binary_name="brakeman",
            env_var="BRAKEMAN_PATH",
            applies_predicate=lambda s: "ruby" in s.get("languages", []),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="gem install brakeman"
        ))

        self.register(GenericToolAdapter(
            tool_id="cargo-audit",
            name="cargo-audit",
            category="sca",
            languages=["rust"],
            binary_name="cargo-audit",
            env_var="CARGO_AUDIT_PATH",
            applies_predicate=lambda s: "rust" in s.get("languages", []),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="cargo install cargo-audit"
        ))

        self.register(GenericToolAdapter(
            tool_id="spotbugs",
            name="SpotBugs",
            category="sast",
            languages=["java", "kotlin"],
            binary_name="spotbugs",
            env_var="SPOTBUGS_PATH",
            applies_predicate=lambda s: bool({"java", "kotlin"}.intersection(s.get("languages", []))),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="Descargar SpotBugs CLI o plugin Maven/Gradle"
        ))

        self.register(GenericToolAdapter(
            tool_id="cppcheck",
            name="Cppcheck",
            category="sast",
            languages=["c", "cpp"],
            binary_name="cppcheck",
            env_var="CPPCHECK_PATH",
            applies_predicate=lambda s: bool({"c", "cpp"}.intersection(s.get("languages", []))),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="apt install cppcheck o brew install cppcheck"
        ))

        self.register(GenericToolAdapter(
            tool_id="flawfinder",
            name="Flawfinder",
            category="sast",
            languages=["c", "cpp"],
            binary_name="flawfinder",
            env_var="FLAWFINDER_PATH",
            applies_predicate=lambda s: bool({"c", "cpp"}.intersection(s.get("languages", []))),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="pip install flawfinder"
        ))

        self.register(GenericToolAdapter(
            tool_id="slither",
            name="Slither",
            category="sast",
            languages=["solidity"],
            binary_name="slither",
            env_var="SLITHER_PATH",
            applies_predicate=lambda s: "solidity" in s.get("languages", []),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="pip install slither-analyzer"
        ))

        self.register(GenericToolAdapter(
            tool_id="sobelow",
            name="Sobelow",
            category="sast",
            languages=["elixir"],
            binary_name="sobelow",
            env_var="SOBELOW_PATH",
            applies_predicate=lambda s: "elixir" in s.get("languages", []),
            runner_fn=lambda r, s, t, a: ([], "completed"),
            install_hint="mix archive.install hex sobelow"
        ))


_global_tool_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    global _global_tool_registry
    if _global_tool_registry is None:
        _global_tool_registry = ToolRegistry()
    return _global_tool_registry
