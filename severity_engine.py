"""Context-aware severity engine with security controls inventory integration,
OWASP Top 10 2021 categorization, rule-based scoring, and remediation SLAs.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT_DIR = Path(__file__).resolve().parent
_DATA_DIR = _ROOT_DIR / "data"
_CWE_OWASP_FILE = _DATA_DIR / "cwe_owasp_2021.json"
_CONTROLS_FILE = _DATA_DIR / "controls_inventory.json"

_SEVERITY_LEVELS: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_LEVEL_TO_SEVERITY: Dict[int, str] = {
    0: "low",
    1: "medium",
    2: "high",
    3: "critical",
}

_REMEDIATION_DEADLINES: Dict[str, str] = {
    "critical": "48 horas",
    "high": "30 días",
    "medium": "90 días",
    "low": "180 días",
}

_CWE_OWASP_CACHE: Optional[Dict[str, str]] = None
_CONTROLS_CACHE: Optional[List[Dict[str, Any]]] = None


def normalize_cwe_string(raw: Any) -> str:
    """Normalize any CWE representation (string, int, list, verbose rule) to 'CWE-XXX'."""
    if isinstance(raw, (list, tuple, set)):
        if not raw:
            return "CWE-Other"
        raw = next(iter(raw))
    raw_str = str(raw or "").strip()
    match = re.search(r"CWE-(\d+)", raw_str, re.IGNORECASE)
    if match:
        return f"CWE-{int(match.group(1))}"
    if raw_str.isdigit():
        return f"CWE-{int(raw_str)}"
    return "CWE-Other"


def load_cwe_owasp_map() -> Dict[str, str]:
    """Load CWE to OWASP 2021 mapping from data/cwe_owasp_2021.json."""
    global _CWE_OWASP_CACHE
    if _CWE_OWASP_CACHE is not None:
        return _CWE_OWASP_CACHE

    mapping: Dict[str, str] = {}
    if _CWE_OWASP_FILE.is_file():
        try:
            with open(_CWE_OWASP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for k, v in data.items():
                        norm_k = normalize_cwe_string(k)
                        mapping[norm_k] = str(v)
        except Exception:
            pass

    _CWE_OWASP_CACHE = mapping
    return mapping


def load_controls_inventory() -> List[Dict[str, Any]]:
    """Load Security Controls Inventory from data/controls_inventory.json."""
    global _CONTROLS_CACHE
    if _CONTROLS_CACHE is not None:
        return _CONTROLS_CACHE

    controls: List[Dict[str, Any]] = []
    if _CONTROLS_FILE.is_file():
        try:
            with open(_CONTROLS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "controls" in data:
                    controls = list(data["controls"])
        except Exception:
            pass

    _CONTROLS_CACHE = controls
    return controls


def resolve_owasp_category(cwe_val: Any, current_owasp: Optional[str] = None) -> str:
    """Resolve standard OWASP Top 10 2021 category using data/cwe_owasp_2021.json

    fallback when the scanner rule does not provide one or provides a generic label.
    """
    clean_curr = str(current_owasp or "").strip()
    generic_labels = {
        "", "owasp", "owasp top 10", "security", "security finding",
        "vulnerability", "none", "unknown", "cwe",
    }
    # If a valid specific OWASP 2021 category is already provided, keep it
    if clean_curr.lower() not in generic_labels and re.match(r"^A\d{2}:2021", clean_curr):
        return clean_curr

    norm_cwe = normalize_cwe_string(cwe_val)
    mapping = load_cwe_owasp_map()
    if norm_cwe in mapping:
        return mapping[norm_cwe]

    if clean_curr and clean_curr.lower() not in generic_labels:
        return clean_curr

    return "A05:2021 - Security Misconfiguration"


def match_control_inventory(
    norm_cwe: str, owasp_cat: str
) -> Optional[Dict[str, Any]]:
    """Find corresponding control from the Security Controls Inventory."""
    controls = load_controls_inventory()
    for ctrl in controls:
        ctrl_cwes = [normalize_cwe_string(c) for c in ctrl.get("cwes", [])]
        if norm_cwe in ctrl_cwes:
            return ctrl
    for ctrl in controls:
        ctrl_owasp = [str(o).lower() for o in ctrl.get("owasp", [])]
        if any(owasp_cat.lower().startswith(o[:7].lower()) for o in ctrl_owasp):
            return ctrl
    return None


def _detect_file_exposure(file_path: str) -> Tuple[int, str]:
    """Evaluate file path exposure: HTTP endpoints, auth modules, internal tests."""
    lower = file_path.replace("\\", "/").lower()

    # Test / mock / sample files (very low exposure / internal code)
    if re.search(r"(?:^|/)(?:tests?|specs?|mocks?|fixtures?|examples?|samples?)\b|test_|_test\.", lower):
        return -25, "archivo de pruebas internas"

    # Authentication / authorization / sessions / secrets
    if re.search(r"(?:^|/)(?:auth|login|sessions?|tokens?|jwt|credentials?|passwords?|secrets?|oauth|permissions?)\b", lower):
        return 15, "módulo de autenticación y credenciales"

    # HTTP routes / controllers / web APIs
    if re.search(r"(?:^|/)(?:api|routes?|controllers?|endpoints?|handlers?|views?|server|app|main)\b|\.(?:router|ctrl)\.", lower):
        return 12, "ruta HTTP o controlador expuesto"

    # IaC / Containers / Workflows
    if re.search(r"(?:dockerfile|\.github/|\.tf$|cloudformation)", lower):
        return 5, "archivo de configuración de infraestructura"

    return 0, "código base"


def _extract_cvss_score(finding: Dict[str, Any]) -> Optional[float]:
    """Extract CVSS score float if present in OSV/finding data."""
    extra = finding.get("extra") or {}
    cvss_val = extra.get("cvss") or finding.get("cvss")
    if isinstance(cvss_val, (int, float)):
        return float(cvss_val)
    if isinstance(cvss_val, str):
        clean_cvss = re.sub(r"^CVSS:\d+\.\d+/?", "", cvss_val.strip(), flags=re.IGNORECASE)
        match = re.search(r"(\d+(?:\.\d+)?)", clean_cvss)
        if match:
            try:
                score = float(match.group(1))
                if 0.0 <= score <= 10.0:
                    return score
            except ValueError:
                pass
    # Check package block or raw references
    title = str(finding.get("title") or "")
    problem = str(finding.get("problem") or "")
    m = re.search(r"cvss\s*(?:v\d+)?\s*[:=]?\s*(\d+(?:\.\d+)?)", f"{title} {problem}", re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return None


def calculate_finding_severity(
    finding: Dict[str, Any],
    target_dir: Optional[str] = None,
) -> Tuple[str, str, str]:
    """Calculate contextual severity using rule-based scoring and controls inventory.

    Returns:
        (severity, severity_reason, remediation_deadline)
    """
    file_path = str(finding.get("file") or "")
    tools = list(finding.get("tools") or [])
    rule = str(finding.get("rule") or "").lower()
    raw_sev = str(finding.get("severity") or "").lower()
    norm_cwe = normalize_cwe_string(finding.get("cwe"))
    owasp_cat = resolve_owasp_category(norm_cwe, finding.get("owasp"))

    # 1. Match against Security Controls Inventory
    matched_ctrl = match_control_inventory(norm_cwe, owasp_cat)

    # Base score from matched control or raw tool severity
    if matched_ctrl:
        ctrl_ref = str(matched_ctrl.get("reference_criticality", "medium")).lower()
        base_points = {"critical": 70, "high": 50, "medium": 30, "low": 15}.get(ctrl_ref, 35)
        ctrl_name = matched_ctrl.get("name")
        ctrl_num = matched_ctrl.get("number")
        control_context = f"Control {ctrl_num}: {ctrl_name}"
    else:
        base_points = {"critical": 70, "high": 50, "medium": 30, "low": 15}.get(raw_sev, 30)
        control_context = None

    score = base_points

    # 2. Tool reported severity adjustment
    if raw_sev == "critical":
        score += 15
    elif raw_sev == "high":
        score += 8
    elif raw_sev == "low":
        score -= 10

    # 3. Type detection and adjustment
    is_secret = (
        "gitleaks" in tools or "trufflehog" in tools or
        rule.startswith("gitleaks/") or rule.startswith("trufflehog/") or
        norm_cwe in ("CWE-798", "CWE-259")
    )
    is_dep = (
        "osv-scanner" in tools or "pip-audit" in tools or "npm-audit" in tools or
        "dependabot" in tools or "deptry" in tools or "depcheck" in tools or
        bool(finding.get("package")) or norm_cwe in ("CWE-1104", "CWE-937")
    )

    finding_type_desc = "vulnerabilidad en código"

    if is_secret:
        finding_type_desc = "secreto o credencial expuesta"
        verification = str(finding.get("verification") or "").upper()
        if verification == "VALID":
            score += 25
            finding_type_desc = "credencial verificada y activa"
        elif verification == "INVALID":
            score -= 15
            finding_type_desc = "secreto no verificado o inválido"
        else:
            score += 15
    elif is_dep:
        finding_type_desc = "dependencia vulnerable"
        cvss = _extract_cvss_score(finding)
        if cvss is not None:
            if cvss >= 9.0:
                score += 25
                finding_type_desc = f"dependencia crítica (CVSS {cvss})"
            elif cvss >= 7.0:
                score += 15
                finding_type_desc = f"dependencia de alto riesgo (CVSS {cvss})"
            elif cvss >= 4.0:
                score += 5
                finding_type_desc = f"dependencia de severidad media (CVSS {cvss})"
            else:
                score -= 10
                finding_type_desc = f"dependencia de bajo impacto (CVSS {cvss})"
        else:
            if raw_sev == "critical":
                score += 18
            elif raw_sev == "high":
                score += 10
    else:
        # Code vulnerability specific impact
        if any(term in rule for term in ("rce", "command-injection", "sqli", "sql-injection", "code-injection")) or norm_cwe in ("CWE-78", "CWE-89", "CWE-94", "CWE-95"):
            score += 15
            finding_type_desc = "inyección crítica o ejecución remota de comandos"
        elif any(term in rule for term in ("xss", "path-traversal", "traversal", "deserialization")) or norm_cwe in ("CWE-79", "CWE-22", "CWE-502"):
            score += 8
            finding_type_desc = "vulnerabilidad de acceso o inyección en aplicación"

    # 4. File exposure adjustment
    exp_delta, exp_desc = _detect_file_exposure(file_path)
    score += exp_delta

    # Confidence modifier
    confidence = str(finding.get("confidence") or "").lower()
    if confidence == "high":
        score += 5
    elif confidence == "low":
        score -= 10

    # 5. Map final score to severity level
    if score >= 75:
        severity = "critical"
    elif score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "low"

    # 6. Compose clear single-sentence severity_reason
    reason_parts = [f"Severidad {severity}: {finding_type_desc} en {exp_desc}"]
    if control_context:
        reason_parts.append(f"asociado al {control_context}")
    severity_reason = f"{', '.join(reason_parts)}."

    # 7. Remediation deadline according to Control 6
    remediation_deadline = _REMEDIATION_DEADLINES.get(severity, "180 días")

    return severity, severity_reason, remediation_deadline


def validate_model_severity_change(
    current_severity: str,
    new_severity: str,
    justification: Optional[str],
) -> Tuple[bool, str, str]:
    """Enforce strict constraints on AI model severity adjustments:

    - Can adjust at most ONE level up or down.
    - MUST provide an explicit, non-empty justification.
    - Any invalid change is strictly rejected, retaining the original severity.

    Returns:
        (is_accepted, final_severity, rejection_or_acceptance_reason)
    """
    curr_clean = str(current_severity or "").lower()
    new_clean = str(new_severity or "").lower()
    just_clean = str(justification or "").strip()

    if curr_clean not in _SEVERITY_LEVELS:
        curr_clean = "medium"

    if new_clean not in _SEVERITY_LEVELS:
        return False, curr_clean, f"Severidad inválida '{new_severity}' propuesta por el modelo; se conserva '{curr_clean}'."

    curr_lvl = _SEVERITY_LEVELS[curr_clean]
    new_lvl = _SEVERITY_LEVELS[new_clean]

    # No change proposed
    if curr_lvl == new_lvl:
        return True, curr_clean, "Sin cambio de severidad."

    # Enforce maximum 1 level difference
    if abs(new_lvl - curr_lvl) > 1:
        return (
            False,
            curr_clean,
            f"El modelo intentó mover la severidad {abs(new_lvl - curr_lvl)} niveles ('{curr_clean}' a '{new_clean}'); el código solo permite 1 nivel como máximo.",
        )

    # Enforce mandatory justification
    if not just_clean or len(just_clean) < 5 or just_clean.lower() in ("none", "n/a", "no", "justification"):
        return (
            False,
            curr_clean,
            f"El modelo propuso cambiar severidad de '{curr_clean}' a '{new_clean}' sin justificación válida; cambio rechazado.",
        )

    return True, new_clean, f"Ajuste de severidad aceptado (1 nivel): {just_clean}"
