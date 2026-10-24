"""Gate de severidad para CI.

Falla (exit 1) si hay hallazgos con severidad >= CHECK_FAIL_SEVERITY.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
SEMGREP_LEVEL_MAP = {"ERROR": "critical", "WARNING": "medium", "INFO": "low"}


def _rule_severity(rule_result: Dict[str, Any]) -> str:
    """Severidad de un resultado Semgrep: criticidad del proyecto o level nativo."""
    metadata = (rule_result.get("extra") or {}).get("metadata") or {}
    criticidad = str(metadata.get("criticidad") or "").upper()
    if criticidad in ("CRITICO", "CRÍTICO"):
        return "critical"
    if criticidad == "ALTO":
        return "high"
    if criticidad == "MEDIO":
        return "medium"
    level = str((rule_result.get("extra") or {}).get("severity") or "INFO").upper()
    return SEMGREP_LEVEL_MAP.get(level, "low")


def blocking_findings(semgrep_path: Path, gitleaks_path: Path,
                      fail_severity: str) -> List[Dict[str, Any]]:
    threshold = SEVERITY_RANK.get(fail_severity, SEVERITY_RANK["critical"])
    blocking: List[Dict[str, Any]] = []

    if semgrep_path.is_file():
        try:
            data = json.loads(semgrep_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("::error::semgrep-results.json no es JSON válido")
            raise SystemExit(2)
        for raw in data.get("results") or []:
            severity = _rule_severity(raw)
            if SEVERITY_RANK.get(severity, 0) >= threshold:
                blocking.append({
                    "tool": "semgrep",
                    "severity": severity,
                    "rule": raw.get("check_id"),
                    "file": raw.get("path"),
                    "line": (raw.get("start") or {}).get("line"),
                })

    if gitleaks_path.is_file():
        try:
            secrets = json.loads(gitleaks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("::error::gitleaks-results.json no es JSON válido")
            raise SystemExit(2)
        for raw in secrets or []:
            blocking.append({
                "tool": "gitleaks",
                "severity": "critical",
                "rule": raw.get("RuleID") or raw.get("Description") or "secret",
                "file": raw.get("File"),
                "line": raw.get("StartLine"),
            })
    return blocking


def main() -> None:
    parser = argparse.ArgumentParser(description="Gate de severidad de seguridad para CI")
    parser.add_argument("--semgrep", default="semgrep-results.json", type=Path)
    parser.add_argument("--gitleaks", default="gitleaks-results.json", type=Path)
    parser.add_argument("--fail-severity", default=None,
                        help="critical | high | medium | low (default env CHECK_FAIL_SEVERITY o critical)")
    args = parser.parse_args()

    import os
    fail_severity = (args.fail_severity
                     or os.environ.get("CHECK_FAIL_SEVERITY", "critical")).strip().lower()
    if fail_severity not in SEVERITY_RANK:
        print(f"::error::CHECK_FAIL_SEVERITY inválida: {fail_severity}")
        raise SystemExit(2)

    blocking = blocking_findings(args.semgrep, args.gitleaks, fail_severity)
    for finding in blocking:
        print(f"::error file={finding.get('file')},line={finding.get('line')}"
              f"::[{finding['severity']}] {finding['tool']}: {finding['rule']}")

    if blocking:
        print(f"GATE: {len(blocking)} hallazgo(s) con severidad >= {fail_severity} "
              "bloquean el merge (controles 9 y 20 del inventario v1.0).")
        raise SystemExit(1)
    print(f"GATE OK: sin hallazgos con severidad >= {fail_severity}.")


if __name__ == "__main__":
    main()
