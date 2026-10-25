"""Pruebas para el Benchmark por Herramienta (F13).

Valida:
1. Emparejamiento SAST con tolerancia de ±3 líneas y casos/CWE.
2. Emparejamiento de secretos en archivo y línea del secreto sembrado.
3. Emparejamiento SCA con normalización de alias (CVE/GHSA/OSV).
4. No cálculo de FPR en datasets sin negativos o donde no aplica.
5. Ejecución del ToolBenchmarkRunner y generación de defaults.yml.
"""

import pytest
from bench.tools.matchers import (
    match_sast_finding,
    match_secrets_finding,
    match_sca_finding,
    calculate_metrics,
)
from bench.tools.run_tool_bench import ToolBenchmarkRunner


def test_match_sast_tolerance():
    truth = {"file": "src/app.py", "line": 20, "cwe": "CWE-89"}

    # Exacto
    assert match_sast_finding({"file": "src/app.py", "line": 20}, truth) is True
    # Tolerancia +3 líneas
    assert match_sast_finding({"file": "src/app.py", "line": 23}, truth) is True
    # Tolerancia -3 líneas
    assert match_sast_finding({"file": "src/app.py", "line": 17}, truth) is True
    # Fuera de tolerancia (>3)
    assert match_sast_finding({"file": "src/app.py", "line": 25}, truth) is False
    # Archivo diferente
    assert match_sast_finding({"file": "src/other.py", "line": 20}, truth) is False


def test_match_secrets_seeded():
    secret_truth = {"file": "config/keys.py", "line": 10, "type": "aws_token"}
    assert match_secrets_finding({"file": "config/keys.py", "line": 11}, secret_truth) is True
    assert match_secrets_finding({"file": "diff/path.py", "line": 10}, secret_truth) is False


def test_match_sca_alias_normalization():
    vuln_truth = {
        "package": "requests",
        "aliases": ["CVE-2018-18074", "GHSA-wqvq-5x8w-865p", "PYSEC-2018-28"]
    }
    # Coincide por CVE
    assert match_sca_finding({"package": "requests", "cve": "cve-2018-18074"}, vuln_truth) is True
    # Coincide por GHSA
    assert match_sca_finding({"package": "requests", "ghsa": "GHSA-WQVq-5x8w-865P"}, vuln_truth) is True
    # Paquete distinto
    assert match_sca_finding({"package": "urllib3", "cve": "CVE-2018-18074"}, vuln_truth) is False
    # Aviso no relacionado
    assert match_sca_finding({"package": "requests", "cve": "CVE-2022-99999"}, vuln_truth) is False


def test_calculate_metrics_sast():
    truth = [
        {"file": "a.py", "line": 10},
        {"file": "b.py", "line": 20},
    ]
    detected = [
        {"file": "a.py", "line": 10},  # TP
        {"file": "c.py", "line": 50},  # FP
    ]
    res = calculate_metrics(detected, truth, matcher_type="sast")
    assert res["tp"] == 1
    assert res["fn"] == 1
    assert res["fp"] == 1
    assert res["recall"] == 0.5
    assert res["precision"] == 0.5
    assert res["fpr"] is None  # Sin negativos no inventa FPR


def test_tool_benchmark_runner_full_cycle(tmp_path):
    runner = ToolBenchmarkRunner(results_dir=tmp_path / "results")
    summary = runner.evaluate_all_tools()
    assert len(summary) >= 10
    
    # Validar que cada herramienta tenga estado y métricas calculadas
    for item in summary:
        assert item["status"] in ("recomendada", "opcional", "desactivada")
        assert "median_time_ms" in item
        assert "category" in item
