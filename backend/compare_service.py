"""Comparación de análisis por repositorio (F9).

El inventario de controles exige revisar si los hallazgos de auditorías
anteriores se cerraron: esta utilidad compara dos análisis del MISMO
repositorio y clasifica cada hallazgo como nuevo, corregido o persistente,
usando la misma huella (regla + archivo + línea) que el webhook de GitHub
(`webhook_service.finding_fingerprint`).
"""

from typing import Any, Dict, List

from webhook_service import finding_fingerprint

MATCH_NOTE = (
    "El emparejamiento usa la huella regla+archivo+línea (la misma del webhook): "
    "un cambio que mueva las líneas puede reportar el mismo problema como "
    "corregido + nuevo."
)


def _normalize_repo_url(url: Any) -> str:
    value = str(url or "").strip().lower().rstrip("/")
    if value.endswith(".git"):
        value = value[: -len(".git")]
    return value


def analysis_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    repository = result.get("repository") or {}
    return {
        "analysis_id": result.get("analysis_id"),
        "url": repository.get("url"),
        "branch": repository.get("branch"),
        "commit": repository.get("commit"),
        "created_at": result.get("created_at"),
        "summary": result.get("summary"),
    }


def compare_analyses(base: Dict[str, Any], target: Dict[str, Any]) -> Dict[str, Any]:
    """Compara dos análisis completos del mismo repositorio.

    - `new` (nuevos): presentes solo en el análisis target.
    - `fixed` (corregidos): presentes solo en el análisis base.
    - `persistent` (persistentes): presentes en ambos.

    Lanza ValueError si falta la URL del repositorio o si los análisis
    pertenecen a repositorios distintos.
    """
    base_url = (base.get("repository") or {}).get("url") or ""
    target_url = (target.get("repository") or {}).get("url") or ""
    if not base_url or not target_url:
        raise ValueError("ambos análisis deben registrar repository.url para poder compararse")
    if _normalize_repo_url(base_url) != _normalize_repo_url(target_url):
        raise ValueError("los análisis pertenecen a repositorios distintos")

    base_findings: List[Dict[str, Any]] = base.get("findings") or []
    target_findings: List[Dict[str, Any]] = target.get("findings") or []
    base_fingerprints = {finding_fingerprint(f) for f in base_findings}
    target_fingerprints = {finding_fingerprint(f) for f in target_findings}

    new = [f for f in target_findings if finding_fingerprint(f) not in base_fingerprints]
    fixed = [f for f in base_findings if finding_fingerprint(f) not in target_fingerprints]
    persistent = [f for f in target_findings if finding_fingerprint(f) in base_fingerprints]

    return {
        "repository": _normalize_repo_url(base_url),
        "base": analysis_meta(base),
        "target": analysis_meta(target),
        "new": new,
        "fixed": fixed,
        "persistent": persistent,
        "counts": {
            "new": len(new),
            "fixed": len(fixed),
            "persistent": len(persistent),
        },
        "note": MATCH_NOTE,
    }
