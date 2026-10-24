"""Agente redactor (F9): explica hallazgos y arma la guía de buenas prácticas.

Determinista, como `fixer_agent`: no consume claves ni modelos de IA. Trabaja
exclusivamente con los campos reales del resultado del análisis; si un dato
falta, lo declara explícitamente ("Dato no disponible: ...") en lugar de
inventarlo. Nunca agrega CWE, categorías OWASP ni recomendaciones que no
provengan de hallazgos reales del análisis.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

GAP_PREFIX = "Dato no disponible"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_LABEL = {
    "critical": "crítica",
    "high": "alta",
    "medium": "media",
    "low": "baja",
}
_MAX_PRACTICES_PER_CATEGORY = 5


def _gap(what: str) -> str:
    return f"{GAP_PREFIX}: {what}."


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def explain_finding(finding: Dict[str, Any]) -> List[str]:
    """Explica un hallazgo usando solo sus campos reales.

    Devuelve una lista de líneas de texto. Cada dato faltante se declara con
    el prefijo "Dato no disponible" — nunca se reemplaza por contenido
    inventado.
    """
    severity = finding.get("severity")
    file_name = finding.get("file")
    line = finding.get("line")
    title = finding.get("title")
    rule = finding.get("rule")
    problem = finding.get("problem")
    solution = finding.get("solution")
    severity_reason = finding.get("severity_reason")
    cwe_list = finding.get("cwe") or []

    location = "ubicación no registrada"
    if file_name:
        location = str(file_name)
        if line:
            location = f"{location}:{line}"
    elif not line:
        location = f"{_gap('ubicación del hallazgo (archivo y línea)')}"

    severity_text = _SEVERITY_LABEL.get(severity, severity)
    if not severity_text:
        severity_text = _gap("severidad")

    lines: List[str] = []
    finding_id = finding.get("id")
    header = f"Hallazgo {finding_id}" if finding_id is not None else "Hallazgo"
    lines.append(f"{header} — severidad {severity_text} — {location}.")

    if finding.get("false_positive"):
        triage_verdict = (finding.get("triage") or {}).get("verdict")
        if triage_verdict:
            lines.append(f"Estado de triage: marcado como falso positivo ({triage_verdict}).")
        else:
            lines.append("Estado de triage: marcado como falso positivo.")

    if title:
        lines.append(f"¿Qué es? {title}.")
    elif rule:
        lines.append(f"¿Qué es? {_gap('título descriptivo')} Regla de detección: {rule}.")
    else:
        lines.append(f"¿Qué es? {_gap('título descriptivo y regla de detección')}")

    if problem:
        lines.append(f"Detalle: {str(problem).strip()}")
    else:
        lines.append(f"Detalle: {_gap('descripción del problema')}")

    if severity_reason:
        lines.append(f"¿Por qué tiene esta severidad? {severity_reason}")
    else:
        lines.append(f"¿Por qué tiene esta severidad? {_gap('justificación de severidad')}")

    if cwe_list:
        lines.append(f"Clasificación: {', '.join(str(c) for c in cwe_list)}.")
    else:
        lines.append(f"Clasificación: {_gap('CWE')}")

    if solution:
        lines.append(f"Cómo corregirlo: {str(solution).strip()}")
    else:
        lines.append(f"Cómo corregirlo: {_gap('solución sugerida para este hallazgo')}")

    remediation = finding.get("remediation") or {}
    remediation_status = remediation.get("status") or finding.get("status") or "open"
    lines.append(f"Estado de remediación: {remediation_status}.")

    return lines


def build_best_practices_guide(result: Dict[str, Any]) -> Dict[str, Any]:
    """Construye la guía de buenas prácticas solo con hallazgos reales.

    Agrupa los hallazgos por su categoría OWASP real (`finding.owasp`) y deriva
    cada práctica de la `solution` real de esos hallazgos. No se agregan
    categorías ni prácticas sin respaldo en hallazgos del análisis.
    """
    findings = result.get("findings") or []
    sections: List[Dict[str, Any]] = []

    if not findings:
        return {
            "sections": [],
            "note": (
                "El análisis no registró hallazgos: la guía se construye únicamente "
                "a partir de hallazgos reales y por eso no tiene secciones."
            ),
        }

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        category = finding.get("owasp")
        if not category:
            rule = finding.get("rule")
            category = f"Sin categoría OWASP (regla {rule})" if rule else _gap("categoría OWASP")
        grouped.setdefault(str(category), []).append(finding)

    for category, group in grouped.items():
        practices: List[str] = []
        seen: set = set()
        missing_solution = 0
        for finding in group:
            solution = finding.get("solution")
            if not solution:
                missing_solution += 1
                continue
            text = str(solution).strip()
            if text and text not in seen:
                seen.add(text)
                if len(practices) < _MAX_PRACTICES_PER_CATEGORY:
                    practices.append(text)
        section: Dict[str, Any] = {
            "category": category,
            "finding_count": len(group),
            "practices": practices,
            "supporting_findings": [f.get("id") for f in group],
        }
        if missing_solution:
            section["note"] = (
                f"{missing_solution} hallazgo(s) de esta categoría no tienen solución "
                "documentada en el análisis."
            )
        if not practices:
            section["note"] = (
                "Ningún hallazgo de esta categoría tiene solución documentada en el "
                "análisis: no se agregan prácticas para no inventar recomendaciones."
            )
        sections.append(section)

    sections.sort(key=lambda item: _section_min_severity(item["supporting_findings"], findings))
    return {
        "sections": sections,
        "note": "Cada sección proviene exclusivamente de hallazgos reales de este análisis.",
    }


def _section_min_severity(finding_ids: List[Any], findings: List[Dict[str, Any]]) -> int:
    by_id = {f.get("id"): f for f in findings}
    order = len(_SEVERITY_ORDER)
    for finding_id in finding_ids:
        finding = by_id.get(finding_id) or {}
        order = min(order, _SEVERITY_ORDER.get(finding.get("severity"), len(_SEVERITY_ORDER)))
    return order


def collect_data_gaps(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """Lista los datos que faltan en el análisis (transparencia, no invención)."""
    gaps: List[Dict[str, str]] = []
    repository = result.get("repository") or {}
    for field in ("commit", "branch"):
        if not repository.get(field):
            gaps.append({"scope": "repository", "field": field})

    findings = result.get("findings") or []
    if not findings:
        gaps.append({"scope": "analysis", "field": "findings (el análisis no registró hallazgos)"})
    for finding in findings:
        finding_id = finding.get("id")
        for field in ("title", "problem", "solution", "severity_reason", "file", "cwe", "owasp"):
            value = finding.get(field)
            if not value or (field == "cwe" and not list(value)):
                gaps.append({"scope": f"finding {finding_id}", "field": field})
        if not finding.get("line"):
            gaps.append({"scope": f"finding {finding_id}", "field": "line"})
    return gaps


def build_writer_report(result: Dict[str, Any]) -> Dict[str, Any]:
    """Salida completa del agente redactor para un análisis."""
    findings = result.get("findings") or []
    explanations = []
    for finding in findings:
        explanations.append({
            "finding_id": finding.get("id"),
            "title": finding.get("title") or finding.get("rule") or _gap("título"),
            "severity": finding.get("severity"),
            "explanation": explain_finding(finding),
        })
    explanations.sort(key=lambda item: _SEVERITY_ORDER.get(item.get("severity"), len(_SEVERITY_ORDER)))
    return {
        "generated_at": _now_iso(),
        "finding_explanations": explanations,
        "best_practices_guide": build_best_practices_guide(result),
        "data_gaps": collect_data_gaps(result),
        "note": (
            "Agente redactor determinista: usa solo campos reales del análisis y "
            "declara explícitamente cada dato faltante en lugar de inventarlo."
        ),
    }
