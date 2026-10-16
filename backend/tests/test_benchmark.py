"""Pruebas del benchmark de precisión (servicio + suite CLI).

Suite autónoma: construye un ejemplo pequeño en un directorio temporal y verifica
el parseo de ground truth (formato Juice Shop y BenchmarkPython), el cruce por
archivo con tolerancia de 3 líneas, las métricas (recall, TPR, FPR), la tabla de
puntaje por categoría CWE y una corrida completa con el analizador simulado y la
persistencia aislada en un directorio temporal (no toca storage/ ni bench/results/).

Ejecución:
    python -m unittest discover -s tests -v
"""

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyzer  # noqa: E402
import benchmark_service  # noqa: E402
from benchmark_service import GroundTruthItem  # noqa: E402


# ---------------------------------------------------------------------------
# Ejemplo pequeño: app.py con 3 vulnerabilidades en las líneas 8, 13 y 19.
# Es dato de prueba: nunca se ejecuta.
# ---------------------------------------------------------------------------

MINI_APP = '''"""Mini aplicación vulnerable de ejemplo (dato, nunca se ejecuta)."""
import hashlib
import os


def run_ping(host):
    # Vulnerable: comando construido con entrada no confiable (CWE-78).
    return os.system("ping -c 1 " + host)


def get_user(conn, username):
    # Vulnerable: consulta SQL concatenada (CWE-89).
    query = "SELECT id FROM users WHERE name = '" + username + "'"
    return conn.execute(query)


def hash_password(password):
    # Vulnerable: hash criptográficamente roto (CWE-327).
    return hashlib.md5(password.encode()).hexdigest()
'''

MINI_GT = {
    "vulnerabilities": [
        {"name": "Command Injection", "vuln_code_snippet": "app.py",
         "vuln_line": 8, "cwe": "CWE-78", "category": "Injection"},
        {"name": "SQL Injection", "vuln_code_snippet": "app.py",
         "vuln_line": 13, "cwe": "CWE-89", "category": "Injection"},
        {"name": "Weak Hash", "vuln_code_snippet": "app.py",
         "vuln_line": 19, "cwe": "CWE-327", "category": "Cryptography"},
    ]
}

# Hallazgos simulados del motor: 2 TP, 2 FP (CWE-94 en app.py:2 y CWE-89 en
# helpers.py:8) y 1 FN (CWE-327 de la línea 19 no detectado).
FINDINGS = [
    {"id": 1, "rule": "py-command-injection", "file": "app.py", "line": 8,
     "severity": "critical",
     "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"]},
    {"id": 2, "rule": "py-sql-injection-concat", "file": "app.py", "line": 11,
     "severity": "critical",
     "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
    {"id": 3, "rule": "py-code-injection-eval", "file": "app.py", "line": 2,
     "severity": "critical",
     "cwe": ["CWE-94: Improper Control of Generation of Code"]},
    {"id": 4, "rule": "py-sql-injection-concat", "file": "helpers.py", "line": 8,
     "severity": "critical",
     "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
]


class TestCleanCwe(unittest.TestCase):
    def test_normalization(self):
        cases = [
            ("CWE-78: OS Command Injection", "CWE-78"),
            ("cwe-89", "CWE-89"),
            (["CWE-327: Weak Hash", "otra cosa"], "CWE-327"),
            ([], "CWE-Other"),
            (None, "CWE-Other"),
            ("texto sin cwe", "CWE-Other"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(benchmark_service._clean_cwe(raw), expected)


class TestParseGroundTruth(unittest.TestCase):
    def test_vuln_markers_parses_file_and_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "vulnerabilities.json").write_text(
                json.dumps(MINI_GT), encoding="utf-8")
            items = benchmark_service.parse_ground_truth(repo, "vuln-markers")
            self.assertEqual(len(items), 3)
            self.assertEqual(items[0].file, "app.py")
            self.assertEqual(items[0].line, 8)
            self.assertEqual(items[0].cwe, "CWE-78")
            self.assertEqual(items[1].line, 13)
            self.assertEqual(items[1].cwe, "CWE-89")

    def test_vuln_markers_finds_juice_shop_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "data" / "static"
            nested.mkdir(parents=True)
            (nested / "vulnerabilities.json").write_text(
                json.dumps({"vulnerabilities": [
                    {"name": "x", "vuln_code_snippet": "a.py",
                     "vuln_line": 2, "cwe": "CWE-22"}]}),
                encoding="utf-8")
            items = benchmark_service.parse_ground_truth(Path(tmp), "vuln-markers")
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].file, "a.py")
            self.assertEqual(items[0].cwe, "CWE-22")

    def test_csv_expected_results_per_case_and_cwe(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "expectedresults-0.1.csv").write_text(
                "TestCaseNumber,CWE,Category,Result,Info\n"
                "1,CWE-78,Command Injection,1,os.system\n"
                "2,CWE-89,SQL Injection,1,concat\n"
                "3,CWE-89,SQL Injection,0,safe\n",
                encoding="utf-8")
            items = benchmark_service.parse_ground_truth(repo, "csv-expected-results")
            self.assertEqual(len(items), 2)  # Result=0 se excluye del ground truth
            self.assertEqual(items[0].file, "src/test_1.py")
            self.assertEqual(items[0].rule_id, "testcase-1")
            self.assertEqual(items[0].cwe, "CWE-78")
            self.assertEqual(items[1].file, "src/test_2.py")
            self.assertEqual(items[1].cwe, "CWE-89")


class TestMatchFindings(unittest.TestCase):
    GT = [GroundTruthItem(file="app.py", line=10, rule_id="cmd", cwe="CWE-78")]

    def test_line_within_tolerance_matches(self):
        det = [{"file": "src/app.py", "line": 12, "cwe": ["CWE-78: cmd"]}]
        matched, unmatched, tp, fp, fn = benchmark_service.match_findings(list(self.GT), det)
        self.assertEqual((tp, fp, fn), (1, 0, 0))
        self.assertEqual(matched[0]["match_score"], 0.8)
        self.assertEqual(unmatched, [])

    def test_line_beyond_tolerance_without_cwe_is_fp(self):
        det = [{"file": "app.py", "line": 14, "cwe": ["CWE-1: otro"]}]
        matched, unmatched, tp, fp, fn = benchmark_service.match_findings(list(self.GT), det)
        self.assertEqual((tp, fp, fn), (0, 1, 1))
        self.assertFalse(matched[0]["matched"])
        self.assertEqual(len(unmatched), 1)

    def test_file_and_cwe_matches_beyond_tolerance(self):
        det = [{"file": "app.py", "line": 40, "cwe": ["CWE-78: cmd"]}]
        matched, unmatched, tp, fp, fn = benchmark_service.match_findings(list(self.GT), det)
        self.assertEqual((tp, fp, fn), (1, 0, 0))
        self.assertEqual(matched[0]["match_score"], 0.75)

    def test_matching_is_one_to_one(self):
        gt = [GroundTruthItem(file="app.py", line=10, rule_id="cmd", cwe="CWE-78")]
        det = [
            {"file": "app.py", "line": 10, "cwe": ["CWE-78: cmd"]},
            {"file": "app.py", "line": 11, "cwe": ["CWE-78: cmd"]},
        ]
        matched, unmatched, tp, fp, fn = benchmark_service.match_findings(gt, det)
        self.assertEqual((tp, fp, fn), (1, 1, 0))


class TestCalculateMetrics(unittest.TestCase):
    def test_recall_tpr_fpr(self):
        metrics = benchmark_service.calculate_metrics_dict(tp=2, fp=1, fn=2)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["tpr"], 0.5)
        self.assertEqual(metrics["fpr"], 0.333)
        self.assertEqual(metrics["precision"], 0.667)
        self.assertEqual(metrics["f1_score"], 0.572)

    def test_zero_division_guard(self):
        metrics = benchmark_service.calculate_metrics_dict(tp=0, fp=0, fn=0)
        self.assertEqual(metrics["recall"], 0.0)
        self.assertEqual(metrics["tpr"], 0.0)
        self.assertEqual(metrics["fpr"], 0.0)
        self.assertEqual(metrics["f1_score"], 0.0)


class TestCweTable(unittest.TestCase):
    def test_score_per_category(self):
        repos = [{
            "raw_ground_truth": [
                {"cwe": "CWE-78: cmd"}, {"cwe": "CWE-78: cmd2"}, {"cwe": "CWE-89"},
            ],
            "raw_detected": [
                {"cwe": ["CWE-78: cmd"], "matched": True},
                {"cwe": ["CWE-78: cmd"], "matched": True},
                {"cwe": ["CWE-94: eval"], "matched": False},
            ],
        }]
        table = benchmark_service.aggregate_cwe_table(repos)
        by_cwe = {row["cwe"]: row for row in table}
        self.assertEqual(by_cwe["CWE-78"]["total_gt"], 2)
        self.assertEqual(by_cwe["CWE-78"]["tp"], 2)
        self.assertEqual(by_cwe["CWE-78"]["fn"], 0)
        self.assertEqual(by_cwe["CWE-78"]["recall"], 1.0)
        self.assertEqual(by_cwe["CWE-89"]["fn"], 1)
        self.assertEqual(by_cwe["CWE-89"]["recall"], 0.0)
        self.assertEqual(by_cwe["CWE-94"]["detected"], 1)
        self.assertEqual(by_cwe["CWE-94"]["fpr"], 1.0)


class TestRunSmallExample(unittest.TestCase):
    """Corrida completa sobre el ejemplo pequeño con analizador simulado
    y persistencia aislada en un directorio temporal."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)

        self.repo_dir = tmp / "mini-repo"
        self.repo_dir.mkdir()
        (self.repo_dir / "app.py").write_text(MINI_APP, encoding="utf-8")
        (self.repo_dir / "vulnerabilities.json").write_text(
            json.dumps(MINI_GT), encoding="utf-8")

        self.refs = [{
            "id": "repo-mini",
            "url": str(self.repo_dir),
            "name": "Mini Example",
            "type": "synthetic",
            "format": "vuln-markers",
        }]

        self.scanned = []

        def fake_scan(target_dir, progress_callback=None, repo_url=None, enable_ai=True):
            self.scanned.append(
                {"target": target_dir, "repo_url": repo_url, "enable_ai": enable_ai})
            return {"status": "completed", "findings": copy.deepcopy(FINDINGS)}

        self.tmp_runs = tmp / "runs"
        self.tmp_results = tmp / "results"
        self.tmp_runs.mkdir()
        self.tmp_results.mkdir()

        self._patches = [
            patch.object(benchmark_service, "RUNS_DIR", self.tmp_runs),
            patch.object(benchmark_service, "BENCH_RESULTS_DIR", self.tmp_results),
            patch.object(benchmark_service, "LATEST_RUN_FILE", self.tmp_runs / "latest.json"),
            patch.object(benchmark_service, "HISTORY_FILE", self.tmp_runs / "history.json"),
            patch.object(benchmark_service, "BASELINE_FILE", self.tmp_runs / "baseline.json"),
            patch.object(benchmark_service, "load_references",
                         lambda refs_file=None: list(self.refs)),
            patch.object(benchmark_service.analyzer, "analyze_directory", fake_scan),
            patch.object(benchmark_service, "get_semgrep_version",
                         lambda: "semgrep-test-1.0"),
            patch.object(benchmark_service, "get_git_commit", lambda path: "f" * 40),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_run_small_example(self):
        out = benchmark_service.execute_benchmark_task(feature_name="prueba-feature")

        # El motor se ejecutó sin IA: los datos del repo analizado no salen de la máquina.
        self.assertEqual(len(self.scanned), 1)
        self.assertFalse(self.scanned[0]["enable_ai"])
        self.assertEqual(self.scanned[0]["repo_url"], str(self.repo_dir))

        summary = out["summary"]
        self.assertEqual(summary["true_positives"], 2)
        self.assertEqual(summary["false_positives"], 2)
        self.assertEqual(summary["false_negatives"], 1)
        self.assertEqual(summary["avg_recall"], 0.667)
        self.assertEqual(summary["avg_tpr"], 0.667)
        self.assertEqual(summary["avg_fpr"], 0.5)

        # Metadata exigida: versión de Semgrep, reglas y commit evaluado.
        self.assertEqual(out["metadata"]["semgrep_version"], "semgrep-test-1.0")
        rules = out["metadata"]["rules"]
        self.assertEqual(rules["registry_configs"], ["p/owasp-top-ten"])
        self.assertIsInstance(rules["local_rule_ids"], list)
        self.assertEqual(out["metadata"]["tool_commit"], "f" * 40)
        self.assertEqual(out["repositories"][0]["commit"], "f" * 40)

        # Puntaje por categoría: el CWE-327 no detectado aparece como FN.
        by_cwe = {row["cwe"]: row for row in out["cwe_categories"]}
        self.assertEqual(by_cwe["CWE-327"]["fn"], 1)
        self.assertEqual(by_cwe["CWE-327"]["recall"], 0.0)
        self.assertEqual(by_cwe["CWE-78"]["tp"], 1)

        # La corrida quedó guardada en bench/results/ (aislado en tmp) junto con
        # latest, historial y baseline automática de la primera corrida.
        run_id = out["run_id"]
        saved = self.tmp_results / f"{run_id}.json"
        self.assertTrue(saved.exists())
        data = json.loads(saved.read_text(encoding="utf-8"))
        self.assertEqual(data["run_id"], run_id)
        self.assertIn("metadata", data)
        self.assertTrue((self.tmp_results / "benchmark-results.json").exists())
        self.assertTrue((self.tmp_runs / f"{run_id}.json").exists())
        self.assertTrue((self.tmp_runs / "latest.json").exists())
        self.assertTrue((self.tmp_runs / "baseline.json").exists())
        history = json.loads((self.tmp_runs / "history.json").read_text(encoding="utf-8"))
        self.assertEqual(history[0]["run_id"], run_id)

    def test_repo_ids_filter(self):
        with self.assertRaises(RuntimeError):
            benchmark_service.execute_benchmark_task(
                feature_name="filtro-vacio", repo_ids=["no-existe"])
        # El estado del servicio debe quedar libre para la siguiente corrida.
        self.assertFalse(benchmark_service._bench_state["is_running"])


def _semgrep_available() -> bool:
    if shutil.which("semgrep") or os.environ.get("SEMGREP_PATH"):
        return True
    analyzer_dir = Path(analyzer.__file__).resolve().parent
    return (
        analyzer_dir.joinpath(".venv", "bin", "semgrep").is_file()
        or analyzer_dir.parent.joinpath(".venv", "bin", "semgrep").is_file()
    )


@unittest.skipUnless(_semgrep_available(), "requiere Semgrep instalado")
class TestSemgrepIntegration(unittest.TestCase):
    def test_engine_detects_small_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.py").write_text(MINI_APP, encoding="utf-8")
            try:
                result = analyzer.analyze_directory(tmp, enable_ai=False)
            except RuntimeError as exc:
                self.skipTest(f"Semgrep no disponible (¿sin red para el registry?): {exc}")
            self.assertEqual(result["status"], "completed")
            self.assertGreaterEqual(result["summary"]["total"], 1)
            for finding in result["findings"]:
                self.assertIn("file", finding)
                self.assertIn("line", finding)
                self.assertIn("severity", finding)


if __name__ == "__main__":
    unittest.main()
