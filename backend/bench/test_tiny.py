#!/usr/bin/env python3
"""
Corrida de ejemplo pequeño (smoke test) del benchmark.

Ejecuta el motor de análisis sobre el dataset pequeño "repo-tiny-example"
(bench/examples/tiny-vuln-app) usando el mismo pipeline que la CLI principal:
clon/copia a carpeta ignorada por git, matching contra ground truth y persistencia
en bench/results/. Requiere Semgrep instalado y disponible en el PATH.

Uso:
    python bench/test_tiny.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import benchmark_service

REPO_ID = "repo-tiny-example"


def run_tiny_example() -> dict:
    """Corrida de benchmark contra el ejemplo pequeño y resumen legible."""
    run_output = benchmark_service.execute_benchmark_task(
        feature_name="ejemplo pequeño",
        repo_ids=[REPO_ID],
    )

    repo = run_output["repositories"][0]
    metrics = repo["metrics"]
    summary = run_output["summary"]

    print("=" * 60)
    print(f"Benchmark con ejemplo pequeño: {repo['name']}")
    print("=" * 60)
    print(f"Corrida: {run_output['run_id']}")
    print(f"Versión de Semgrep: {run_output['metadata']['semgrep_version']}")
    print(f"Commit evaluado (referencia): {repo.get('commit') or 'copia local sin git'}")
    print(f"Ground truth: {repo['ground_truth_count']} hallazgos esperados")
    print(f"Detectados:   {repo['findings_detected']} hallazgos")
    print(f"Métricas: TP={metrics['true_positives']} FP={metrics['false_positives']} "
          f"FN={metrics['false_negatives']}")
    print(f"  Recall: {metrics['recall']:.2%}  TPR: {metrics['tpr']:.2%}  "
          f"FPR: {metrics['fpr']:.2%}  F1: {metrics['f1_score']:.3f}")
    print(f"Resumen global de la corrida: {summary}")
    print(f"Resultados guardados en bench/results/{run_output['run_id']}.json")
    return run_output


if __name__ == "__main__":
    try:
        run_tiny_example()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
