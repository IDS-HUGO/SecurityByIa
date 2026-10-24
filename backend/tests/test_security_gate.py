"""Pruebas para el gate de severidad de CI (scripts/security_gate.py)."""

import json
import pytest
from pathlib import Path

from scripts.security_gate import (
    SEVERITY_RANK,
    _rule_severity,
    blocking_findings,
)


class TestSecurityGate:
    def test_rule_severity_mapping(self):
        # Metadata del proyecto
        assert _rule_severity({"extra": {"metadata": {"criticidad": "CRITICO"}}}) == "critical"
        assert _rule_severity({"extra": {"metadata": {"criticidad": "ALTO"}}}) == "high"
        assert _rule_severity({"extra": {"metadata": {"criticidad": "MEDIO"}}}) == "medium"

        # Level estándar de Semgrep
        assert _rule_severity({"extra": {"severity": "ERROR"}}) == "critical"
        assert _rule_severity({"extra": {"severity": "WARNING"}}) == "medium"
        assert _rule_severity({"extra": {"severity": "INFO"}}) == "low"

    def test_blocking_findings_semgrep_critical(self, tmp_path):
        semgrep_file = tmp_path / "semgrep.json"
        gitleaks_file = tmp_path / "gitleaks.json"
        semgrep_file.write_text(json.dumps({
            "results": [
                {
                    "check_id": "rules.sql-injection",
                    "path": "app.py",
                    "start": {"line": 10},
                    "extra": {"metadata": {"criticidad": "CRITICO"}}
                },
                {
                    "check_id": "rules.cors-wildcard",
                    "path": "app.py",
                    "start": {"line": 20},
                    "extra": {"metadata": {"criticidad": "MEDIO"}}
                }
            ]
        }))
        gitleaks_file.write_text("[]")

        # Con umbral critical, solo el hallazgo crítico bloquea
        blocking = blocking_findings(semgrep_file, gitleaks_file, "critical")
        assert len(blocking) == 1
        assert blocking[0]["tool"] == "semgrep"
        assert blocking[0]["severity"] == "critical"
        assert blocking[0]["rule"] == "rules.sql-injection"

        # Con umbral medium, ambos bloquean
        blocking_med = blocking_findings(semgrep_file, gitleaks_file, "medium")
        assert len(blocking_med) == 2

    def test_blocking_findings_gitleaks_secret(self, tmp_path):
        semgrep_file = tmp_path / "semgrep.json"
        gitleaks_file = tmp_path / "gitleaks.json"
        semgrep_file.write_text(json.dumps({"results": []}))
        gitleaks_file.write_text(json.dumps([
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Key",
                "File": "config.py",
                "StartLine": 5,
            }
        ]))

        blocking = blocking_findings(semgrep_file, gitleaks_file, "critical")
        assert len(blocking) == 1
        assert blocking[0]["tool"] == "gitleaks"
        assert blocking[0]["severity"] == "critical"
        assert blocking[0]["rule"] == "aws-access-token"

    def test_clean_scan_produces_no_blocking(self, tmp_path):
        semgrep_file = tmp_path / "semgrep.json"
        gitleaks_file = tmp_path / "gitleaks.json"
        semgrep_file.write_text(json.dumps({"results": []}))
        gitleaks_file.write_text("[]")

        blocking = blocking_findings(semgrep_file, gitleaks_file, "critical")
        assert len(blocking) == 0

    def test_missing_files_produce_no_blocking(self, tmp_path):
        semgrep_file = tmp_path / "missing_semgrep.json"
        gitleaks_file = tmp_path / "missing_gitleaks.json"

        blocking = blocking_findings(semgrep_file, gitleaks_file, "critical")
        assert len(blocking) == 0

    def test_malformed_json_exits(self, tmp_path):
        semgrep_file = tmp_path / "semgrep.json"
        gitleaks_file = tmp_path / "gitleaks.json"
        semgrep_file.write_text("not json")
        gitleaks_file.write_text("[]")

        with pytest.raises(SystemExit) as exc:
            blocking_findings(semgrep_file, gitleaks_file, "critical")
        assert exc.value.code == 2
