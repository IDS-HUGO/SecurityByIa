"""Constructores de reportes (F9): SARIF 2.1.0, Markdown enriquecido y resumen ejecutivo.

Todas las funciones son puras sobre el dict de resultado del análisis (el mismo
JSON persistido en `storage/analyses/`) y usan solo datos reales: si un dato
falta, se declara explícitamente (ver `writer_agent`).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

import writer_agent
from webhook_service import finding_fingerprint

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Security Control Center"

# SARIF 2.1.0 solo acepta error | warning | note | none.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEVERITIES = ("critical", "high", "medium", "low")
_REMEDIATION_STATES = ("open", "patch_proposed", "verified", "discarded", "approved", "rejected")
_TOP_FINDINGS_LIMIT = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return result.get("findings") or []


def severity_counts(result: Dict[str, Any]) -> Dict[str, int]:
    """Conteo real por severidad, recalculado de los hallazgos.

    El `summary` persistido se usa solo como respaldo cuando no hay hallazgos
    de donde recontear (p. ej. resultados de error sin findings).
    """
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in _findings(result):
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    if not any(counts.values()):
        summary = result.get("summary") or {}
        for severity in _SEVERITIES:
            counts[severity] = int(summary.get(severity) or 0)
    counts["total"] = sum(counts.values())
    return counts


def remediation_counts(result: Dict[str, Any]) -> Dict[str, int]:
    """Estado de remediación real (F6) contado de `finding.remediation.status`."""
    counts = {state: 0 for state in _REMEDIATION_STATES}
    for finding in _findings(result):
        status = (finding.get("remediation") or {}).get("status") or finding.get("status") or "open"
        if status not in counts:
            counts[status] = 0
        counts[status] += 1
    return counts


def _repository_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    repository = result.get("repository") or {}
    missing = [field for field in ("url", "name", "branch", "commit") if not repository.get(field)]
    meta = {field: repository.get(field) for field in ("url", "name", "branch", "commit")}
    meta["missing_fields"] = missing
    return meta


def build_sarif_report(result: Dict[str, Any]) -> Dict[str, Any]:
    """Exporta el análisis a SARIF 2.1.0 (un `run` con las reglas vistas)."""
    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for finding in _findings(result):
        rule_id = finding.get("rule") or "unknown-rule"
        if rule_id not in rules:
            rule: Dict[str, Any] = {"id": rule_id}
            title = finding.get("title")
            if title:
                rule["name"] = str(title)[:120]
            references = finding.get("references") or []
            if references:
                rule["helpUri"] = str(references[0])
            properties: Dict[str, Any] = {}
            if finding.get("cwe"):
                properties["cwe"] = [str(c) for c in finding["cwe"]]
            if finding.get("owasp"):
                properties["owasp"] = finding["owasp"]
            if properties:
                rule["properties"] = properties
            rules[rule_id] = rule

        severity = finding.get("severity")
        message_parts = [str(part).strip() for part in (finding.get("title"), finding.get("problem")) if part]
        message_text = ". ".join(message_parts) if message_parts else f"Regla {rule_id}"

        location: Dict[str, Any] = {}
        file_name = finding.get("file")
        if file_name:
            artifact: Dict[str, Any] = {"uri": str(file_name)}
            physical: Dict[str, Any] = {"artifactLocation": artifact}
            if finding.get("line"):
                physical["region"] = {"startLine": int(finding["line"])}
            location = {"physicalLocation": physical}

        sarif_results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": message_text},
            "locations": [location] if location else [],
            "partialFingerprints": {"securityControlCenter/v1": finding_fingerprint(finding)},
            "properties": {
                "findingId": finding.get("id"),
                "severity": severity,
                "remediationStatus": (finding.get("remediation") or {}).get("status") or "open",
                "falsePositive": bool(finding.get("false_positive")),
            },
        })

    repository = _repository_meta(result)
    coverage = result.get("coverage") or {}
    notifications = []
    for gap in coverage.get("gaps") or []:
        notifications.append({
            "descriptor": {"id": "coverage-gap"},
            "message": {"text": f"Laguna de cobertura detectada: {gap}"},
            "level": "warning"
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "rules": list(rules.values())}},
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": _now_iso(),
                **({"toolExecutionNotifications": notifications} if notifications else {})
            }],
            "properties": {
                "analysisId": result.get("analysis_id"),
                "repository": {k: v for k, v in repository.items() if k != "missing_fields"},
                "summary": severity_counts(result),
                "remediation": remediation_counts(result),
                "coverage": coverage,
            },
            "results": sarif_results,
        }],
    }


def build_markdown_report(result: Dict[str, Any]) -> str:
    """Reporte enriquecido (F9): SHA, fecha, severidades, remediación y redactor."""
    repository = _repository_meta(result)
    generated = result.get("created_at") or _now_iso()
    counts = severity_counts(result)
    remediation = remediation_counts(result)
    writer = writer_agent.build_writer_report(result)
    guide = writer["best_practices_guide"]
    coverage = result.get("coverage") or {}

    def meta_line(label: str, value: Any) -> str:
        return f"- **{label}:** {value}" if value else f"- **{label}:** {writer_agent.GAP_PREFIX.lower()}: {label.lower()}."

    lines: List[str] = []
    repo_name = repository.get("name") or repository.get("url")
    lines.append(f"# Informe de seguridad — {repo_name}" if repo_name else "# Informe de seguridad — Security Control Center")
    lines += [""]
    lines += [
        meta_line("Repositorio", repository.get("url")),
        meta_line("Rama", repository.get("branch")),
        meta_line("Commit (SHA)", repository.get("commit")),
        meta_line("Fecha de análisis", generated),
        meta_line("ID de análisis", result.get("analysis_id")),
        f"- **Estado:** {result.get('status') or writer_agent.GAP_PREFIX.lower()}: estado.",
        "",
        "## Cobertura del análisis (F14)",
        "",
        f"- **Estado de cobertura:** `{coverage.get('status', 'completed')}`",
    ]

    if coverage.get("languages"):
        lines.append("- **Lenguajes detectados:**")
        for lang in coverage["languages"]:
            lines.append(f"  - `{lang.get('name')}`: {lang.get('files')} archivos (SAST: {lang.get('sast') or 'ninguno'}, SCA: {lang.get('sca') or 'ninguno'})")

    if coverage.get("gaps"):
        lines.append("- **Lagunas de cobertura declaradas:**")
        for gap in coverage["gaps"]:
            lines.append(f"  - ⚠️ {gap}")
        lines.append("  *(Principio de cobertura: nunca se reporta 'limpio' sin cobertura completa; la revisión con IA asiste como cubierta parcial)*")

    lines += [
        "",
        "## Resumen por severidad",
        "",
        f"Total de hallazgos: **{counts['total']}**.",
        "",
        "| Severidad | Cantidad |",
        "| :--- | :--- |",
    ]
    for severity in _SEVERITIES:
        lines.append(f"| {severity} | {counts[severity]} |")

    lines += ["", "## Estado de remediación", ""]
    for state in _REMEDIATION_STATES:
        lines.append(f"- `{state}`: {remediation[state]}")
    if any(remediation[state] for state in _REMEDIATION_STATES if state != "open"):
        lines.append("")
        lines.append("Los estados distintos de `open` provienen del bucle de remediación asistida (F6).")

    lines += ["", "## Hallazgos", ""]
    for finding in _findings(result):
        location = finding.get("file") or "ubicación no registrada"
        if finding.get("line"):
            location = f"{location}:{finding['line']}"
        lines.append(f"### [{finding.get('id')}] {finding.get('title') or finding.get('rule') or 'Hallazgo'} — {location}")
        lines.append("")
        for explanation_line in writer_agent.explain_finding(finding):
            lines.append(f"- {explanation_line}")
        lines.append("")

    lines += ["## Guía de buenas prácticas (agente redactor)", ""]
    if guide.get("note"):
        lines.append(f"> {guide['note']}")
        lines.append("")
    for section in guide.get("sections") or []:
        lines.append(f"### {section['category']} — {section['finding_count']} hallazgo(s)")
        lines.append("")
        if section.get("practices"):
            for practice in section["practices"]:
                lines.append(f"- {practice}")
        if section.get("note"):
            lines.append(f"- *{section['note']}*")
        lines.append("")

    gaps = writer.get("data_gaps") or []
    lines += ["## Datos faltantes declarados", ""]
    if gaps:
        for gap in gaps:
            lines.append(f"- `{gap['scope']}` → falta `{gap['field']}`.")
    else:
        lines.append("- Ninguno: el análisis registró todos los campos que este informe usa.")
    lines.append("")

    return "\n".join(lines)


def build_executive_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Resumen ejecutivo de una página (para la vista imprimible del dashboard)."""
    writer = writer_agent.build_writer_report(result)
    counts = severity_counts(result)
    by_id = {f.get("id"): f for f in _findings(result)}
    top = []
    for item in writer["finding_explanations"]:
        if len(top) >= _TOP_FINDINGS_LIMIT:
            break
        finding = by_id.get(item.get("finding_id")) or {}
        top.append({
            "id": item.get("finding_id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "remediation_status": (finding.get("remediation") or {}).get("status") or "open",
            "explanation": item.get("explanation") or [],
        })
    repository = _repository_meta(result)
    return {
        "analysis_id": result.get("analysis_id"),
        "status": result.get("status"),
        "generated_at": _now_iso(),
        "analyzed_at": result.get("created_at"),
        "repository": repository,
        "severity_counts": counts,
        "remediation_counts": remediation_counts(result),
        "top_findings": top,
        "best_practices_guide": writer["best_practices_guide"],
        "data_gaps": writer["data_gaps"],
        "note": (
            "Resumen ejecutivo de una página construido solo con datos reales del "
            "análisis; los datos faltantes se listan al pie."
        ),
    }
