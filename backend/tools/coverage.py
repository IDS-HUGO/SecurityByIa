"""Cálculo y auditoría de Cobertura Declarada del Análisis (F14).

Garantiza que el análisis nunca informe falsamente un estado 'limpio' cuando
determinados lenguajes o componentes quedaron sin revisar.
Genera el bloque 'coverage' y determina si el análisis finaliza en
'completed' o 'completed_with_gaps'.
"""

from typing import Any, Dict, List, Optional


# Mapeo de herramientas SAST y SCA conocidas por lenguaje
_LANGUAGE_SAST_COVERAGE = {
    "python": ["semgrep", "bandit"],
    "javascript": ["semgrep"],
    "typescript": ["semgrep"],
    "node": ["semgrep"],
    "go": ["semgrep", "gosec"],
    "java": ["semgrep", "spotbugs"],
    "kotlin": ["semgrep"],
    "ruby": ["semgrep", "brakeman"],
    "php": ["semgrep"],
    "rust": ["semgrep"],
    "csharp": ["semgrep"],
    "dotnet": ["semgrep"],
    "cpp": ["cppcheck", "flawfinder", "semgrep"],
    "c": ["cppcheck", "flawfinder", "semgrep"],
    "solidity": ["slither"],
    "dart": ["semgrep"],
}

_LANGUAGE_SCA_COVERAGE = {
    "python": ["osv-scanner", "pip-audit"],
    "javascript": ["osv-scanner", "npm-audit"],
    "typescript": ["osv-scanner", "npm-audit"],
    "node": ["osv-scanner", "npm-audit"],
    "go": ["osv-scanner", "govulncheck"],
    "java": ["osv-scanner"],
    "kotlin": ["osv-scanner"],
    "ruby": ["osv-scanner", "bundler-audit"],
    "php": ["osv-scanner"],
    "rust": ["osv-scanner", "cargo-audit"],
    "csharp": ["osv-scanner"],
    "dotnet": ["osv-scanner"],
    "dart": ["osv-scanner"],
    "elixir": ["osv-scanner"],
}


def build_coverage_block(
    stack: Dict[str, Any],
    tools_status: Dict[str, str],
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Construye el bloque de cobertura declarada para el resultado del análisis."""
    stats = stack.get("languages_stats") or {}
    languages_list: List[Dict[str, Any]] = []
    gaps: List[str] = []

    # Herramientas activas o ejecutadas con éxito/degradadas
    active_tools = {
        name for name, st in tools_status.items()
        if st in ("completed", "ok", "degraded")
    }

    # Recorrer lenguajes detectados con archivos
    for lang, data in stats.items():
        files_count = data.get("files", 0)
        bytes_count = data.get("bytes", 0)
        if files_count == 0:
            continue

        # Verificar qué herramienta cubrió SAST
        possible_sast = _LANGUAGE_SAST_COVERAGE.get(lang, [])
        applied_sast = [t for t in possible_sast if t in active_tools]

        # Verificar qué herramienta cubrió SCA
        possible_sca = _LANGUAGE_SCA_COVERAGE.get(lang, [])
        applied_sca = [t for t in possible_sca if t in active_tools]

        sast_desc = ", ".join(applied_sast) if applied_sast else None
        sca_desc = ", ".join(applied_sca) if applied_sca else None

        # Si no hay herramienta SAST que aplique o corra
        if not sast_desc:
            gaps.append(f"{lang}: sin herramienta SAST dedicada disponible en el entorno")

        languages_list.append({
            "name": lang,
            "files": files_count,
            "bytes": bytes_count,
            "sast": sast_desc,
            "sca": sca_desc,
        })

    # Revisar herramientas de IaC o CI degradadas o con error
    if stack.get("terraform") and tools_status.get("checkov") in ("degraded", "error", "unavailable"):
        gaps.append(f"terraform: checkov no disponible o degradado ({tools_status.get('checkov')})")

    if stack.get("dockerfiles") and tools_status.get("hadolint") in ("unavailable", "error"):
        gaps.append("dockerfile: hadolint no disponible para auditoría de contenedor")

    # Determinar estado de la cobertura
    if gaps:
        status = "completed_with_gaps"
    else:
        status = "completed"

    return {
        "status": status,
        "languages": languages_list,
        "gaps": gaps,
        "ai_review_recommended": bool(gaps),
        "total_languages": len(languages_list),
        "summary": f"{len(languages_list)} lenguaje(s) detectado(s), {len(gaps)} laguna(s) de cobertura identificada(s)."
    }
