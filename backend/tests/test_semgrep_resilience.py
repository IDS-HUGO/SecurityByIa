"""Pruebas de resiliencia de Semgrep (fallback y status degraded)."""

import json
import subprocess

import pytest

import analyzer


class FakeProc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


FULL_RESULTS = {
    "results": [
        {"check_id": "python.test.r1", "path": "/tmp/x/app.py", "start": {"line": 3},
         "extra": {"metadata": {"cwe": "CWE-89"}, "message": "sql", "lines": "x = 1",
                   "severity": "ERROR"}},
    ]
}


def local_results(target):
    return {
        "results": [
            {"check_id": "py-sql-injection-concat", "path": str(target / "app.py"),
             "start": {"line": 3},
             "extra": {"metadata": {"cwe": "CWE-89"}, "message": "sql", "lines": "x = 1",
                       "severity": "ERROR"}},
            {"check_id": "py-command-injection", "path": str(target / "app.py"),
             "start": {"line": 9},
             "extra": {"metadata": {"cwe": "CWE-78"}, "message": "cmd", "lines": "y = 2",
                       "severity": "ERROR"}},
        ]
    }


def capture_calls(monkeypatch, outcomes):
    """Sustituye subprocess.run de analyzer por una cola de respuestas."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return outcomes.pop(0)

    monkeypatch.setattr(analyzer.subprocess, "run", fake_run)
    return calls


def progress_noop(stage, percentage, message):
    pass


class TestSemgrepStage:
    def test_exit_2_en_run_completa_y_reintenta_con_locales(self, monkeypatch, tmp_path):
        target = tmp_path
        """Simula exit code 2 (registro caído): reintento con locales y degraded."""
        calls = capture_calls(monkeypatch, [
            FakeProc(2, stdout="", stderr="registry unreachable"),
            FakeProc(0, stdout=json.dumps(local_results(target))),
        ])
        data, status = analyzer._run_semgrep_stage(
            "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
            "/tmp/x", None, progress_noop)
        assert status == "degraded"
        assert len(data["results"]) == 2
        assert len(calls) == 2
        # la primera corrida incluyó el ruleset extendido; la segunda no
        assert any("p/owasp-top-ten" in " ".join(cmd) for cmd in calls[:1])
        assert all("p/owasp-top-ten" not in " ".join(cmd) for cmd in calls[1:])

    def test_todo_fallido_lanza_y_no_reporta_limpio(self, monkeypatch, tmp_path):
        target = tmp_path
        capture_calls(monkeypatch, [
            FakeProc(2, stdout="", stderr="registry unreachable"),
            FakeProc(2, stdout="", stderr="local rules broken"),
        ])
        with pytest.raises(RuntimeError, match="no reportar"):
            analyzer._run_semgrep_stage(
                "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
                str(target), None, progress_noop)

    def test_json_invalido_reintenta(self, monkeypatch, tmp_path):
        target = tmp_path
        capture_calls(monkeypatch, [
            FakeProc(0, stdout="no es json"),
            FakeProc(0, stdout=json.dumps(local_results(target))),
        ])
        _, status = analyzer._run_semgrep_stage(
            "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
            "/tmp/x", None, progress_noop)
        assert status == "degraded"

    def test_error_de_regla_invalida_y_reintenta(self, monkeypatch, tmp_path):
        target = tmp_path
        """Un RuleParseError en el JSON invalida la corrida aunque exit sea 0."""
        bad_rule = {**FULL_RESULTS,
                    "errors": [{"type": "RuleParseError", "message": "bad rule"}]}
        capture_calls(monkeypatch, [
            FakeProc(0, stdout=json.dumps(bad_rule)),
            FakeProc(0, stdout=json.dumps(local_results(target))),
        ])
        _, status = analyzer._run_semgrep_stage(
            "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
            "/tmp/x", None, progress_noop)
        assert status == "degraded"

    def test_parse_error_de_target_no_degrada(self, monkeypatch, tmp_path):
        target = tmp_path
        """Los ParseError de archivos del target son normales: corrida completa."""
        data_in = {**FULL_RESULTS,
                   "errors": [{"type": "ParseError", "path": "/tmp/x/raro.py",
                               "message": "cannot parse"}]}
        capture_calls(monkeypatch, [FakeProc(0, stdout=json.dumps(data_in))])
        _, status = analyzer._run_semgrep_stage(
            "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
            "/tmp/x", None, progress_noop)
        assert status == "completed"

    def test_run_completa_ok_no_reintenta(self, monkeypatch, tmp_path):
        target = tmp_path
        calls = capture_calls(monkeypatch, [FakeProc(0, stdout=json.dumps(FULL_RESULTS))])
        _, status = analyzer._run_semgrep_stage(
            "semgrep", ["/rules/local.yml"], ["p/owasp-top-ten"],
            "/tmp/x", None, progress_noop)
        assert status == "completed"
        assert len(calls) == 1


class TestAnalyzeDirectoryResilience:
    def _mock_pipeline(self, monkeypatch):
        monkeypatch.setattr(analyzer, "_run_gitleaks", lambda *a, **k: ([], "unavailable"))
        monkeypatch.setattr(analyzer.scanner_tools, "run_tools",
                            lambda *a, **k: {"findings": [], "tools": {}, "stack": {},
                                             "sbom": None, "licenses": None, "scorecard": None})
        monkeypatch.delenv("ENABLE_CONTROLS_REVIEW", raising=False)
        monkeypatch.delenv("ENABLE_AI_TRIAGE", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def test_degradado_no_dice_completado_limpio(self, monkeypatch, tmp_path):
        """Criterio de aceptación P0-1: exit 2 simulado → el resultado NUNCA
        dice 'completado limpio'; marca warnings y semgrep degraded."""
        self._mock_pipeline(monkeypatch)
        (tmp_path / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")

        def fake_stage(semgrep_bin, local_configs, extended_configs, target_dir, budget, progress):
            return local_results(tmp_path), "degraded"

        monkeypatch.setattr(analyzer, "_run_semgrep_stage", fake_stage)
        result = analyzer.analyze_directory(str(tmp_path), enable_ai=False,
                                            progress_callback=None)
        assert result["analysis"]["tools"]["semgrep"] == "degraded"
        assert result.get("warnings")
        assert "degradado" in result["warnings"][0].lower()
        # hay hallazgos reales de las reglas locales (no un repo «limpio»)
        assert result["summary"]["total"] >= 1
        assert result["status"] == "completed" and result["summary"]["total"] > 0

    def test_todo_fallido_termina_failed(self, monkeypatch, tmp_path):
        """Sin Semgrep (local y extendido) el análisis falla: no hay «limpio»."""
        self._mock_pipeline(monkeypatch)

        def failing_stage(*args, **kwargs):
            raise RuntimeError("Semgrep falló también con las reglas locales")

        monkeypatch.setattr(analyzer, "_run_semgrep_stage", failing_stage)
        with pytest.raises(RuntimeError, match="reglas locales"):
            analyzer.analyze_directory(str(tmp_path), enable_ai=False, progress_callback=None)
