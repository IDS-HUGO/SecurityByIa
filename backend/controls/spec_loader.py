"""Carga y validación de las especificaciones de controles (inventario v1.0).

Las 35 especificaciones viven en `backend/controls/specs/` como datos YAML
(una por control: 1..22 y C1..C13). La lógica no conoce controles específicos
salvo el gating declarado en cada spec (`aplica_con_llm`).
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
SPECS_DIR = Path(__file__).resolve().parent / "specs"
ROOT_CONTROLS_DIR = REPO_ROOT / "controls"

REQUIRED_FIELDS = (
    "id", "nombre", "categoria_owasp", "criticidad_referencia", "familia",
    "metodo", "donde_buscar", "senales_incumplimiento", "falsos_positivos",
    "herramientas", "ia_revisa", "remediacion", "verificacion",
    "criterio_aceptacion", "fragmentos_regex",
)
VALID_METODOS = {"repo", "en_vivo", "en vivo", "nube", "evidencia"}
VALID_CRITICIDAD = {"CRITICO", "ALTO", "MEDIO", "COMPLEMENTARIO"}
EXPECTED_IDS = [str(n) for n in range(1, 23)] + [f"C{n}" for n in range(1, 14)]
LLM_ONLY_IDS = {"C10", "C11", "C12", "C13"}
JUSTIFICACION_NO_APLICA = (
    "El repositorio no usa un SDK de modelos de lenguaje "
    "(sin dependencias de LLM detectadas en manifiestos)."
)

KEY_ALIASES = {
    "referencia": "categoria_owasp",
    "dónde buscar": "donde_buscar",
    "dónde_buscar": "donde_buscar",
    "señales de incumplimiento": "senales_incumplimiento",
    "señales_incumplimiento": "senales_incumplimiento",
    "falsos positivos conocidos": "falsos_positivos",
    "falsos_positivos_conocidos": "falsos_positivos",
    "remediación": "remediacion",
    "verificación": "verificacion",
    "método": "metodo",
}


def normalize_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Normaliza alias de campos en español y aplica valores predeterminados seguros."""
    # Convertir id a str
    if "id" in spec:
        spec["id"] = str(spec["id"])
    for alias, target in KEY_ALIASES.items():
        if alias in spec and target not in spec:
            spec[target] = spec[alias]
        elif target in spec and alias not in spec:
            spec[alias] = spec[target]
    if "metodo" in spec:
        if spec["metodo"] == "en vivo":
            spec["metodo"] = "en_vivo"
        spec["método"] = spec["metodo"]
    if "categoria_owasp" in spec and "referencia" not in spec:
        spec["referencia"] = spec["categoria_owasp"]
    if "criticidad_referencia" not in spec:
        spec["criticidad_referencia"] = "MEDIO"
    if "herramientas" not in spec:
        spec["herramientas"] = ["revision-manual", "curl"]
    if "ia_revisa" not in spec:
        spec["ia_revisa"] = f"Revisar cumplimiento del control {spec.get('nombre', '')}"
    if "criterio_aceptacion" not in spec:
        spec["criterio_aceptacion"] = str(spec.get("verificacion", "Cumplimiento de criterios de seguridad"))
    if "fragmentos_regex" not in spec:
        spec["fragmentos_regex"] = []
    if "aplica_con_llm" not in spec:
        spec["aplica_con_llm"] = False
    return spec


def validate_spec(spec: Dict[str, Any], origin: str = "") -> None:
    """Valida el esquema de una especificación; lanza ValueError si falta algo."""
    normalize_spec(spec)
    for field in REQUIRED_FIELDS:
        value = spec.get(field)
        if value is None or (isinstance(value, (str, list)) and not value):
            raise ValueError(f"spec {origin or spec.get('id')}: campo obligatorio ausente o vacío: {field}")
    if not str(spec["id"]).strip():
        raise ValueError(f"spec {origin}: id vacío")
    if spec["metodo"] not in VALID_METODOS:
        raise ValueError(f"spec {spec['id']}: metodo inválido: {spec['metodo']}")
    if spec["criticidad_referencia"] not in VALID_CRITICIDAD:
        raise ValueError(f"spec {spec['id']}: criticidad inválida: {spec['criticidad_referencia']}")
    for regex in spec["fragmentos_regex"]:
        try:
            re.compile(regex)
        except re.error as exc:
            raise ValueError(f"spec {spec['id']}: regex inválida {regex!r}: {exc}") from exc
    if spec["id"] in LLM_ONLY_IDS:
        if not spec.get("aplica_con_llm"):
            raise ValueError(f"spec {spec['id']}: control de IA debe declarar aplica_con_llm: true")
        if not spec.get("justificacion_no_aplica"):
            raise ValueError(f"spec {spec['id']}: falta justificacion_no_aplica")
    if spec.get("aplica_con_llm") and spec["id"] not in LLM_ONLY_IDS:
        raise ValueError(f"spec {spec['id']}: aplica_con_llm solo corresponde a {sorted(LLM_ONLY_IDS)}")


def load_specs(specs_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Carga todas las especificaciones validadas en orden natural dinámico."""
    directories: List[Path] = []
    if specs_dir:
        directories = [Path(specs_dir)]
    else:
        directories = [SPECS_DIR]
        if ROOT_CONTROLS_DIR.is_dir() and ROOT_CONTROLS_DIR != SPECS_DIR:
            directories.append(ROOT_CONTROLS_DIR)

    specs: Dict[str, Dict[str, Any]] = {}
    for directory in directories:
        paths = sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.yml")))
        for path in paths:
            try:
                spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ValueError(f"spec {path.name}: YAML inválido: {exc}") from exc
            if not isinstance(spec, dict):
                raise ValueError(f"spec {path.name}: el contenido no es un mapping")
            validate_spec(spec, path.name)
            specs[str(spec["id"])] = spec

    missing = [control_id for control_id in EXPECTED_IDS if control_id not in specs]
    if missing:
        raise ValueError(f"faltan especificaciones de controles: {missing}")
    return sorted(specs.values(), key=spec_id_order_key)


# SDKs de modelos de lenguaje que habilitan los controles C10-C13 (tokens de
# dependencia buscados en manifiestos; lista de detección, no criterio del inventario).
_LLM_SDK_TOKENS = (
    "openai", "anthropic", "google-generativeai", "google-genai", "langchain",
    "llama-index", "llama_index", "cohere", "mistralai", "@anthropic-ai/sdk",
    "@google/generative-ai", "@google-cloud/vertexai", "cohere-ai",
    "azure-ai-openai", "groq", "replicate", "dspy-ai", "litellm",
)
_MANIFESTS = (
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "pyproject.toml", "Pipfile", "package.json", "go.mod",
)


def detect_llm_sdk(root: Path) -> Dict[str, Any]:
    """Detecta de forma determinista si el repo usa un SDK de modelos de lenguaje.

    Revisa manifiestos de dependencias en la raíz del repo (y un nivel de
    profundidad) buscando tokens de SDK conocidos. Devuelve el veredicto con
    la evidencia (archivo y coincidencia) que se registra en la revisión.
    """
    root = Path(root)
    evidence: List[Dict[str, str]] = []
    for manifest in _manifest_candidates(root):
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.lower()
        for token in _LLM_SDK_TOKENS:
            if token in lowered:
                evidence.append({"archivo": str(manifest.relative_to(root)), "sdk": token})
                break
    return {"detectado": bool(evidence), "evidencia": evidence}


def _manifest_candidates(root: Path) -> List[Path]:
    candidates: List[Path] = []
    for name in _MANIFESTS:
        candidates.append(root / name)
        for child in sorted(root.iterdir()) if root.is_dir() else []:
            if child.is_dir() and not child.name.startswith(".") and child.name not in (
                "node_modules", "storage", "venv", ".venv", "__pycache__", "dist", "build",
            ):
                candidate = child / name
                if candidate.is_file():
                    candidates.append(candidate)
    seen = set()
    unique = []
    for candidate in candidates:
        resolved = str(candidate)
        if resolved not in seen and candidate.is_file():
            seen.add(resolved)
            unique.append(candidate)
    return unique


def spec_id_order_key(spec: Dict[str, Any]) -> tuple:
    """Orden natural del inventario: numéricos primero (1..23..), luego C (C1..C13..), luego otros."""
    control_id = str(spec.get("id", ""))
    if control_id.startswith("C") and control_id[1:].isdigit():
        return (1, int(control_id[1:]))
    if control_id.isdigit():
        return (0, int(control_id))
    return (2, control_id)


def summarize_specs(specs: List[Dict[str, Any]]) -> str:
    return json.dumps([{"id": s["id"], "nombre": s["nombre"]} for s in specs], ensure_ascii=False)
