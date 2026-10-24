"""Orquestación de la revisión por control (inventario v1.0).

- Empaqueta evidencia de forma determinista (evidence_builder).
- Gate C10-C13: solo aplican si el repo usa un SDK de LLM; si no, quedan
  "no aplica" con la justificación registrada.
- RBAC (12) e IDOR (C2): el agente juzga un endpoint a la vez; la cobertura
  se calcula como endpoints revisados sobre endpoints totales.
- Cruce con scanners: las coincidencias suben la confianza; lo detectado solo
  por el agente va a la cola Por revisar.
- Opt-in: ENABLE_CONTROLS_REVIEW=true (el agente solo lee, nunca ejecuta).
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from controls import spec_loader
from controls.evidence_builder import (
    build_endpoint_package,
    build_package,
    enumerate_endpoints,
    estimate_tokens,
)
from controls.reviewer_agent import review_control
from proxy import client as proxy_client

ENABLE_ENV = "ENABLE_CONTROLS_REVIEW"
MAX_ENDPOINTS_REVIEW_ENV = "CONTROLS_MAX_ENDPOINTS_REVIEW"
DEFAULT_MAX_ENDPOINTS_REVIEW = 20
EVIDENCE_TOKENS_ENV = "SECURITY_CONTROLS_EVIDENCE_TOKENS"
CONFIDENCE_BOOST_CORROBORATED = 0.15
REVIEWER_NAME = "agente-revisor-controles-v1 (solo lectura)"
SCAN_METHODS = {"nube", "evidencia"}

_EVIDENCE_STATES = ("cumple", "parcial", "no cumple", "no aplica", "descartado", "no_evaluado")


def _enabled(explicit: Optional[bool] = None) -> bool:
    if explicit is not None:
        return bool(explicit)
    return os.environ.get(ENABLE_ENV, "false").strip().lower() in ("1", "true", "yes")


def _agent_available() -> bool:
    if proxy_client.proxy_configured():
        return True
    return any(os.environ.get(name, "").strip() for name in
               ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"))


def _scanner_findings_by_control(result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Agrupa hallazgos de scanners por control (metadata.control de las reglas)."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in result.get("findings") or []:
        control = str(finding.get("control") or "").strip()
        if control:
            grouped.setdefault(control, []).append(finding)
    return grouped


def _base_entry(spec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": spec["id"],
        "nombre": spec["nombre"],
        "categoria_owasp": spec["categoria_owasp"],
        "criticidad_referencia": spec["criticidad_referencia"],
        "familia": spec["familia"],
        "metodo": spec["metodo"],
        "estado": "no_evaluado",
        "confianza": 0.0,
        "corroboration": "n/a",
        "veredicto_solo_agente": False,
        "requiere_revision": True,
        "evidencia": [],
        "razonamiento": "",
        "cobertura": None,
    }


def _apply_scanner_cross(entry: Dict[str, Any], scanner_findings: List[Dict[str, Any]]) -> None:
    """Cruce del veredicto del agente con los hallazgos de scanners."""
    verdict = entry["estado"]
    if verdict in ("no cumple", "parcial"):
        if scanner_findings:
            entry["corroboration"] = "scanner+agente"
            entry["confianza"] = min(0.99, round(entry["confianza"] + CONFIDENCE_BOOST_CORROBORATED, 2))
            # Corroborado por scanners: no es "solo agente", sale de la cola Por revisar.
            entry["requiere_revision"] = False
            entry["evidencia"] = entry["evidencia"] + [
                {"archivo": f["file"], "linea": f.get("line") or 0,
                 "fragmento": f"(scanner) {f.get('rule')}"}
                for f in scanner_findings[:3]
            ]
        else:
            entry["corroboration"] = "solo_agente"
            entry["veredicto_solo_agente"] = True
            entry["requiere_revision"] = True
    elif verdict == "cumple" and scanner_findings:
        entry["corroboration"] = "conflicto_scanner"
        entry["veredicto_solo_agente"] = True
        entry["requiere_revision"] = True
        entry["razonamiento"] = (
            f"{entry['razonamiento']} Los scanners reportan "
            f"{len(scanner_findings)} hallazgo(s) de este control: conflicto con el veredicto "
            "del agente, requiere revisión humana."
        )
    elif verdict == "cumple":
        entry["corroboration"] = "agente"
        entry["veredicto_solo_agente"] = True
        entry["requiere_revision"] = False


def _review_endpoint_based(spec: Dict[str, Any], root: Path, reviewer: Callable,
                           max_tokens: Optional[int]) -> Dict[str, Any]:
    """RBAC (12) e IDOR (C2): un endpoint por llamada; cobertura = revisados/total."""
    entry = _base_entry(spec)
    endpoints = enumerate_endpoints(root)
    total = len(endpoints)
    cap = max(1, int(os.environ.get(MAX_ENDPOINTS_REVIEW_ENV, str(DEFAULT_MAX_ENDPOINTS_REVIEW))))
    if total == 0:
        entry["razonamiento"] = ("Sin endpoints detectados en el repositorio: no hay "
                                 "superficie para evaluar el control. Requiere revisión humana.")
        entry["estado"] = "no_evaluado"
        return entry
    selected = endpoints[:cap]
    verdicts: List[Dict[str, Any]] = []
    for endpoint in selected:
        package = build_endpoint_package(spec, root, endpoint, max_tokens)
        if not package.get("archivos"):
            continue
        verdicts.append(reviewer(spec, package))
    reviewed = len(verdicts)
    estados = [v["estado"] for v in verdicts if v.get("estado") in ("cumple", "parcial", "no cumple")]
    coverage = f"{reviewed}/{total}"
    if total > cap:
        coverage += f" (muestreo de {cap} endpoints)"
    entry["cobertura"] = coverage
    if "no cumple" in estados:
        entry["estado"] = "no cumple"
    elif "parcial" in estados:
        entry["estado"] = "parcial"
    elif estados and all(state == "cumple" for state in estados):
        entry["estado"] = "cumple"
    else:
        entry["estado"] = "no_evaluado"
        entry["razonamiento"] = ("No se obtuvo veredicto para ningún endpoint "
                                 "(respuestas descartadas o sin IA).")
        return entry
    worst = next((v for v in verdicts if v.get("estado") == entry["estado"]), verdicts[0])
    entry["confianza"] = min((float(v.get("confianza") or 0.0) for v in verdicts), default=0.0)
    entry["evidencia"] = []
    for verdict in verdicts:
        for item in verdict.get("evidencia") or []:
            entry["evidencia"].append(item)
    entry["evidencia"] = entry["evidencia"][:8]
    entry["razonamiento"] = (
        f"Evaluación endpoint por endpoint (cobertura: {coverage}). "
        f"Estados por endpoint: {estados.count('no cumple')} no cumple, "
        f"{estados.count('parcial')} parcial, {estados.count('cumple')} cumple. "
        f"{worst.get('razonamiento', '')}"
    )[:800]
    return entry


def review_controls(root: Any, result: Dict[str, Any], reviewer: Optional[Callable] = None,
                    max_tokens: Optional[int] = None,
                    enable: Optional[bool] = None) -> Dict[str, Any]:
    """Revisa los 35 controles sobre un análisis. El agente solo lee."""
    root = Path(root)
    if not _enabled(explicit=enable):
        return {"disponible": False,
                "motivo": f"Revisión de controles desactivada (activá {ENABLE_ENV}=true)."}
    try:
        specs = spec_loader.load_specs()
    except ValueError as exc:
        return {"disponible": False, "motivo": f"Especificaciones inválidas: {exc}"}

    llm_sdk = spec_loader.detect_llm_sdk(root)
    repository = result.get("repository") or {}
    findings_by_control = _scanner_findings_by_control(result)
    token_cap = max_tokens or int(os.environ.get(EVIDENCE_TOKENS_ENV, "0") or 0) or None
    if reviewer is None and not _agent_available():
        results = []
        for spec in specs:
            entry = _base_entry(spec)
            if spec["id"] in spec_loader.LLM_ONLY_IDS and not llm_sdk["detectado"]:
                entry["estado"] = "no aplica"
                entry["confianza"] = 1.0
                entry["requiere_revision"] = False
                entry["razonamiento"] = spec_loader.JUSTIFICACION_NO_APLICA
            else:
                entry["razonamiento"] = ("Revisión con IA no configurada (sin proxy de secretos "
                                         "ni claves de proveedor): requiere revisión humana.")
            results.append(entry)
        return _finalize(results, repository, llm_sdk)
    if reviewer is not None:
        evaluator: Callable = reviewer
    else:
        def evaluator(spec: Dict[str, Any], package: Dict[str, Any]) -> Dict[str, Any]:
            return review_control(spec, package)

    results: List[Dict[str, Any]] = []
    for spec in specs:
        entry = _base_entry(spec)
        control_id = spec["id"]
        if control_id in spec_loader.LLM_ONLY_IDS and not llm_sdk["detectado"]:
            entry["estado"] = "no aplica"
            entry["confianza"] = 1.0
            entry["requiere_revision"] = False
            entry["razonamiento"] = spec_loader.JUSTIFICACION_NO_APLICA
            results.append(entry)
            continue
        if control_id in ("12", "C2"):
            entry = _review_endpoint_based(spec, root, evaluator, token_cap)
        else:
            package = build_package(spec, root, token_cap)
            if not package.get("archivos"):
                entry["estado"] = "no_evaluado"
                entry["razonamiento"] = (
                    "Sin archivos de 'dónde buscar' en el repositorio para este control "
                    "(método "
                    f"{spec['metodo']}): requiere revisión en vivo, nube o evidencia humana."
                )
                results.append(entry)
                continue
            entry.update(evaluator(spec, package))
        _apply_scanner_cross(entry, findings_by_control.get(control_id, []))
        results.append(entry)
    return _finalize(results, repository, llm_sdk)


def review_from_stored_findings(result: Dict[str, Any]) -> Dict[str, Any]:
    """Re-derivación honesta de controles SOLO con hallazgos de scanners persistidos.

    Sin el repositorio clonado no hay evidencia de archivos ni llamada al agente:
    un control con hallazgos de scanners queda "no cumple" (decisión de scanner,
    con la evidencia real); el resto queda "no_evaluado" (Por revisar). Nunca se
    fabrican veredictos de cumple por ausencia de hallazgos.
    """
    specs = spec_loader.load_specs()
    findings_by_control = _scanner_findings_by_control(result)
    repository = result.get("repository") or {}
    results: List[Dict[str, Any]] = []
    for spec in specs:
        entry = _base_entry(spec)
        scanner = findings_by_control.get(spec["id"], [])
        if scanner:
            entry["estado"] = "no cumple"
            entry["confianza"] = 0.9
            entry["corroboration"] = "scanner"
            entry["requiere_revision"] = False
            entry["evidencia"] = [
                {"archivo": str(f.get("file")), "linea": int(f.get("line") or 0),
                 "fragmento": f"(scanner) {f.get('rule')}"}
                for f in scanner[:8]
            ]
            entry["razonamiento"] = (
                f"{len(scanner)} hallazgo(s) de scanners con este control en los metadatos "
                "de su regla. Re-revisión derivada del análisis guardado."
            )
        else:
            entry["razonamiento"] = (
                "Re-revisión sin repositorio clonado: solo se derivan veredictos de "
                "scanners. Este control requiere revisión con IA (nuevo análisis con "
                f"{ENABLE_ENV}=true) o evidencia humana."
            )
        results.append(entry)
    return _finalize(results, repository, {
        "detectado": None,
        "evidencia": [],
        "motivo": "sin repositorio clonado: detección de SDK de LLM no disponible",
    })


def _finalize(results: List[Dict[str, Any]], repository: Dict[str, Any],
              llm_sdk: Dict[str, Any]) -> Dict[str, Any]:
    resumen = {state: 0 for state in _EVIDENCE_STATES}
    for entry in results:
        resumen[entry["estado"]] = resumen.get(entry["estado"], 0) + 1
    queue = [entry["id"] for entry in results if entry.get("requiere_revision")]
    return {
        "disponible": True,
        "application": repository.get("name") or repository.get("url"),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "reviewer": REVIEWER_NAME,
        "commit": repository.get("commit"),
        "branch": repository.get("branch"),
        "llm_sdk": llm_sdk,
        "results": results,
        "resumen": resumen,
        "queue_por_revisar": queue,
    }
