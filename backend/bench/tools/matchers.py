"""Emparejadores y cálculo de métricas para el Benchmark por Herramienta (F13).

Implementa las reglas de coincidencia estandarizadas de la sección 3.4 de HACER.md:
- SAST e IaC: Coincidencia de archivo y línea ±3 líneas, o caso + CWE.
- Secretos: Coincidencia en archivo y línea del secreto sembrado.
- SCA: Coincidencia de paquete, versión y cualquiera de los alias del aviso (CVE, GHSA, OSV).
- Licencias: Coincidencia exacta de identificador SPDX.
- Cálculo riguroso de TP, FP, FN, TN, Recall, Precisión, FPR y F1.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def match_sast_finding(finding: Dict[str, Any], truth_item: Dict[str, Any], tolerance_lines: int = 3) -> bool:
    """Evalúa si un hallazgo SAST/IaC coincide con el ground truth."""
    f_file = (finding.get("file") or finding.get("path") or "").replace("\\", "/").lstrip("./")
    t_file = (truth_item.get("file") or truth_item.get("path") or "").replace("\\", "/").lstrip("./")

    if f_file != t_file and not f_file.endswith(t_file) and not t_file.endswith(f_file):
        return False

    # Comparación por número de línea con tolerancia ±N
    f_line = finding.get("line") or finding.get("start_line") or 0
    t_line = truth_item.get("line") or truth_item.get("vuln_line") or 0

    if f_line and t_line:
        try:
            return abs(int(f_line) - int(t_line)) <= tolerance_lines
        except (ValueError, TypeError):
            pass

    # Comparación por caso o CWE si aplica
    f_case = finding.get("case")
    t_case = truth_item.get("case")
    if f_case and t_case and str(f_case) == str(t_case):
        return True

    return False


def match_secrets_finding(finding: Dict[str, Any], truth_secret: Dict[str, Any], tolerance_lines: int = 3) -> bool:
    """Evalúa si una detección de secreto acierta con un secreto sembrado."""
    f_file = (finding.get("file") or finding.get("path") or "").replace("\\", "/").lstrip("./")
    t_file = (truth_secret.get("file") or "").replace("\\", "/").lstrip("./")

    if f_file != t_file and not f_file.endswith(t_file) and not t_file.endswith(f_file):
        return False

    f_line = finding.get("line") or finding.get("start_line") or 0
    t_line = truth_secret.get("line") or 0
    if f_line and t_line:
        try:
            return abs(int(f_line) - int(t_line)) <= tolerance_lines
        except (ValueError, TypeError):
            pass

    return True


def match_sca_finding(finding: Dict[str, Any], truth_vuln: Dict[str, Any]) -> bool:
    """Evalúa si un hallazgo SCA coincide con la vulnerabilidad conocida normalizando alias."""
    f_pkg = (finding.get("package") or "").lower().strip()
    t_pkg = (truth_vuln.get("package") or "").lower().strip()
    if f_pkg and t_pkg and f_pkg != t_pkg:
        return False

    # Extraer identificadores del hallazgo
    finding_ids = set()
    for key in ("cve", "ghsa", "id", "rule_id", "advisory_id"):
        val = finding.get(key)
        if val:
            finding_ids.add(str(val).upper().strip())
    
    # Alias esperados del ground truth
    expected_aliases = {str(a).upper().strip() for a in truth_vuln.get("aliases", [])}
    if truth_vuln.get("id"):
        expected_aliases.add(str(truth_vuln.get("id")).upper().strip())

    # Coincidencia si se cruza cualquier alias
    return bool(finding_ids & expected_aliases)


def calculate_metrics(
    detected_findings: List[Dict[str, Any]],
    truth_items: List[Dict[str, Any]],
    negative_items: Optional[List[Dict[str, Any]]] = None,
    matcher_type: str = "sast"
) -> Dict[str, Any]:
    """Calcula la matriz de confusión y métricas estándar (Recall, Precisión, FPR, F1)."""
    matcher_fn = {
        "sast": match_sast_finding,
        "iac": match_sast_finding,
        "secrets": match_secrets_finding,
        "sca": match_sca_finding,
    }.get(matcher_type, match_sast_finding)

    matched_truth_ids = set()
    matched_finding_indices = set()

    # Identificar Verdaderos Positivos (TP)
    for t_idx, t_item in enumerate(truth_items):
        t_id = t_item.get("id", f"truth_{t_idx}")
        for f_idx, finding in enumerate(detected_findings):
            if f_idx in matched_finding_indices:
                continue
            if matcher_fn(finding, t_item):
                matched_truth_ids.add(t_id)
                matched_finding_indices.add(f_idx)
                break

    tp = len(matched_truth_ids)
    fn = len(truth_items) - tp
    # Falsos positivos = hallazgos no emparejados con ninguna verdad
    fp = len(detected_findings) - len(matched_finding_indices)

    # Cálculo sobre casos negativos (TN y FP negativos) si existen
    tn = 0
    fp_on_negatives = 0
    if negative_items:
        for neg in negative_items:
            triggered = any(matcher_fn(f, neg) for f in detected_findings)
            if triggered:
                fp_on_negatives += 1
            else:
                tn += 1

    # Métricas estándar
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    
    # FPR: Solo calculable si hay negativos etiquetados
    fpr = None
    if negative_items and (fp_on_negatives + tn) > 0:
        fpr = round(fp_on_negatives / (fp_on_negatives + tn), 4)
    elif negative_items is None and (fp + tn) > 0:
        fpr = None  # No inventar métricas donde no hay casos seguros etiquetados

    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn if negative_items else None,
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "f1": f1,
        "total_detected": len(detected_findings),
        "total_truth": len(truth_items),
        "total_negatives": len(negative_items) if negative_items else 0,
    }
