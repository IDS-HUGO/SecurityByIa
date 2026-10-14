#!/usr/bin/env python3
"""
Suite CLI de benchmark de precisión para el motor SAST.

Por cada repositorio de referencia declarado en bench/refs.yml:
  1. Lo resuelve en una carpeta ignorada por git (/tmp/bench-repos-run/<run_id>):
     copia local si la referencia es una ruta, `git clone --depth 1` si es una URL.
  2. Ejecuta el motor de análisis (analyzer.analyze_directory, el mismo pipeline que
     analyzer.analyze_repo usa tras clonar: reglas locales + p/owasp-top-ten + Gitleaks),
     siempre sin IA y sin enviar código ni secretos fuera de la máquina.
  3. Compara los hallazgos con la verdad de referencia según el formato declarado:
     - "vuln-markers" (estilo Juice Shop): vulnerabilities.json con vuln_code_snippet
       (archivo) y vuln_line, cruzadas por archivo con tolerancia de 3 líneas.
     - "csv-expected-results" (estilo BenchmarkPython): expectedresults-0.1.csv,
       un caso de prueba por fila, cruzado por caso y CWE.
  4. Calcula recall, TPR, FPR (además de precisión y F1) globales y por categoría CWE.
  5. Guarda la corrida en bench/results/ junto con la versión de Semgrep, las reglas
     aplicadas y los commits evaluados (herramienta y cada referencia).

Los nombres de los repositorios de referencia son datos de bench/refs.yml: ni el motor
ni este script contienen lógica atada a un repositorio, lenguaje o estructura concreta.

Uso:
    python bench/benchmark.py                                    # todos los refs
    python bench/benchmark.py --repo-ids repo-juice-sample       # un subconjunto
    python bench/benchmark.py --save-as-baseline --feature "fx"  # fijar baseline
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import benchmark_service


def _print_row(columns: List[str], widths: List[int]) -> None:
    print("  ".join(col.ljust(width) for col, width in zip(columns, widths)).rstrip())


def print_report(run_output: Dict[str, Any]) -> None:
    summary = run_output.get("summary", {})
    metadata = run_output.get("metadata", {})
    rules = metadata.get("rules", {})

    print(f"\nCorrida: {run_output.get('run_id')}  ({run_output.get('timestamp')})")
    print(f"Feature: {run_output.get('feature')}")
    print(f"Versión de Semgrep: {metadata.get('semgrep_version', 'unknown')}")
    local_ids = ", ".join(
        rule.get("id", "?") for rule in rules.get("local_rule_ids", [])
    ) or "-"
    print(f"Reglas locales: {rules.get('local_rules_file', '-')} [{local_ids}]")
    registry = ", ".join(rules.get("registry_configs", [])) or "-"
    print(f"Configs del registry: {registry}")
    print(f"Commit de la herramienta evaluada: {metadata.get('tool_commit') or '-'}")

    print("\nResumen global:")
    headers = ["TP", "FP", "FN", "Recall", "TPR", "FPR", "Precisión", "F1"]
    widths = [6, 6, 6, 8, 8, 8, 10, 8]
    _print_row(headers, widths)
    _print_row([
        str(summary.get("true_positives", 0)),
        str(summary.get("false_positives", 0)),
        str(summary.get("false_negatives", 0)),
        f"{summary.get('avg_recall', 0.0):.1%}",
        f"{summary.get('avg_tpr', 0.0):.1%}",
        f"{summary.get('avg_fpr', 0.0):.1%}",
        f"{summary.get('avg_precision', 0.0):.1%}",
        f"{summary.get('avg_f1_score', 0.0):.1%}",
    ], widths)

    print("\nPor repositorio (commit evaluado):")
    for repo in run_output.get("repositories", []):
        metrics = repo.get("metrics", {})
        commit = repo.get("commit") or "copia local sin git"
        print(
            f"  - {repo.get('id')}: GT={repo.get('ground_truth_count', 0)} "
            f"detect={repo.get('findings_detected', 0)} "
            f"recall={metrics.get('recall', 0.0):.1%} "
            f"tpr={metrics.get('tpr', 0.0):.1%} "
            f"fpr={metrics.get('fpr', 0.0):.1%} "
            f"[{commit}]"
        )

    print("\nPuntaje por categoría CWE:")
    headers = ["CWE", "Categoría", "GT", "TP", "FP", "FN", "Recall", "FPR", "F1"]
    widths = [9, 26, 5, 4, 4, 4, 8, 8, 8]
    _print_row(headers, widths)
    for category in run_output.get("cwe_categories", []):
        _print_row([
            category.get("cwe", "-"),
            str(category.get("name", "-"))[:26],
            str(category.get("total_gt", 0)),
            str(category.get("tp", 0)),
            str(category.get("fp", 0)),
            str(category.get("fn", 0)),
            f"{category.get('recall', 0.0):.1%}",
            f"{category.get('fpr', 0.0):.1%}",
            f"{category.get('f1_score', 0.0):.1%}",
        ], widths)

    run_id = run_output.get("run_id", "")
    print(
        f"\nResultados guardados en bench/results/{run_id}.json "
        "(también en benchmark-results.json, latest.json y storage/benchmark/runs/)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark de precisión del motor SAST contra repos de referencia",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--repo-ids",
        nargs="+",
        default=None,
        help="Ejecuta solo estos ids declarados en bench/refs.yml (por defecto: todos)",
    )
    parser.add_argument(
        "--feature",
        default=None,
        help="Etiqueta de la feature evaluada (por defecto: último commit de git)",
    )
    parser.add_argument(
        "--save-as-baseline",
        action="store_true",
        help="Fija esta corrida como baseline.json",
    )
    args = parser.parse_args()

    try:
        run_output = benchmark_service.execute_benchmark_task(
            feature_name=args.feature,
            save_as_baseline=args.save_as_baseline,
            repo_ids=args.repo_ids,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print_report(run_output)


if __name__ == "__main__":
    main()
