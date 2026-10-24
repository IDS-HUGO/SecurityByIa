"""Pruebas de reportes y exportaciones (F9): SARIF 2.1.0, Markdown enriquecido,
resumen ejecutivo, agente redactor, comparación de análisis y endpoints."""

import json

import pytest

import compare_service
import report_builder
import writer_agent


def sample_finding(**overrides):
    finding = {
        "id": 1,
        "rule": "py-sql-injection-concat",
        "owasp": "A03:2021 - Injection",
        "cwe": ["CWE-89"],
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "severity": "critical",
        "severity_reason": "Base CTRL-01 (70) + inyección (+15)",
        "file": "app/db.py",
        "line": 42,
        "title": "SQL injection por concatenación",
        "problem": "La consulta se arma concatenando entrada del usuario.",
        "solution": "Usar consultas parametrizadas.",
        "false_positive": False,
        "status": "open",
        "remediation": {"status": "open"},
    }
    finding.update(overrides)
    return finding


def sample_result(findings=None, **overrides):
    result = {
        "analysis_id": "11111111-2222-3333-4444-555555555555",
        "status": "completed",
        "created_at": "2026-10-20T10:00:00+00:00",
        "repository": {
            "url": "https://github.com/org/repo",
            "name": "repo",
            "branch": "main",
            "commit": "abc123def4567890",
        },
        "summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
        "findings": findings if findings is not None else [
            sample_finding(),
            sample_finding(
                id=2,
                rule="py-hardcoded-secret",
                severity="high",
                severity_reason="Secreto verificado VALID",
                cwe=["CWE-798"],
                owasp="A07:2021 - Identification and Authentication Failures",
                title="Secredo hardcodeado",
                file="app/config.py",
                line=7,
                remediation={"status": "verified"},
            ),
        ],
        "analysis": {"remediation": {}},
    }
    result.update(overrides)
    return result


class TestSarifExport:
    def test_version_and_schema(self):
        sarif = report_builder.build_sarif_report(sample_result())
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == report_builder.SARIF_SCHEMA
        assert len(sarif["runs"]) == 1

    def test_results_and_level_mapping(self):
        sarif = report_builder.build_sarif_report(sample_result())
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["py-sql-injection-concat"] == "error"      # critical → error
        assert levels["py-hardcoded-secret"] == "error"          # high → error
        medium = report_builder.build_sarif_report(sample_result(
            findings=[sample_finding(severity="medium")]))
        assert medium["runs"][0]["results"][0]["level"] == "warning"
        low = report_builder.build_sarif_report(sample_result(
            findings=[sample_finding(severity="low")]))
        assert low["runs"][0]["results"][0]["level"] == "note"

    def test_rules_are_deduplicated_and_carry_metadata(self):
        findings = [sample_finding(), sample_finding(id=2, line=50)]
        sarif = report_builder.build_sarif_report(sample_result(findings=findings))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "py-sql-injection-concat"
        assert rules[0]["properties"]["cwe"] == ["CWE-89"]

    def test_location_and_remediation_status(self):
        sarif = report_builder.build_sarif_report(sample_result())
        second = sarif["runs"][0]["results"][1]
        location = second["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "app/config.py"
        assert location["region"]["startLine"] == 7
        assert second["properties"]["remediationStatus"] == "verified"

    def test_partial_fingerprint_is_stable(self):
        from webhook_service import finding_fingerprint
        sarif = report_builder.build_sarif_report(sample_result())
        result = sarif["runs"][0]["results"][0]
        assert result["partialFingerprints"]["securityControlCenter/v1"] == finding_fingerprint(sample_finding())

    def test_finding_without_file_has_no_locations(self):
        sarif = report_builder.build_sarif_report(sample_result(
            findings=[sample_finding(file=None, line=None)]))
        assert sarif["runs"][0]["results"][0]["locations"] == []

    def test_run_properties_carry_repository_and_summary(self):
        sarif = report_builder.build_sarif_report(sample_result())
        props = sarif["runs"][0]["properties"]
        assert props["repository"]["commit"] == "abc123def4567890"
        assert props["summary"]["total"] == 2
        assert "remediation" in props


class TestMarkdownReport:
    def test_includes_sha_branch_date_and_severities(self):
        md = report_builder.build_markdown_report(sample_result())
        assert "abc123def4567890" in md
        assert "main" in md
        assert "2026-10-20" in md
        assert "| critical | 1 |" in md
        assert "| high | 1 |" in md

    def test_includes_remediation_states(self):
        md = report_builder.build_markdown_report(sample_result())
        assert "`open`: 1" in md
        assert "`verified`: 1" in md

    def test_includes_writer_explanation_and_guide(self):
        md = report_builder.build_markdown_report(sample_result())
        assert "Guía de buenas prácticas" in md
        assert "A03:2021 - Injection" in md
        assert "Usar consultas parametrizadas." in md
        assert "Estado de remediación" in md

    def test_missing_commit_is_declared_not_invented(self):
        result = sample_result()
        result["repository"] = {"url": "https://github.com/org/repo", "name": "repo"}
        md = report_builder.build_markdown_report(result)
        assert "dato no disponible: commit (sha)" in md.lower()


class TestWriterAgent:
    def test_explanation_uses_only_real_fields(self):
        lines = writer_agent.explain_finding(sample_finding())
        text = "\n".join(lines)
        assert "SQL injection por concatenación" in text
        assert "app/db.py:42" in text
        assert "CWE-89" in text
        assert "Usar consultas parametrizadas." in text
        assert "open" in text

    def test_missing_data_is_declared(self):
        finding = sample_finding()
        for field in ("title", "problem", "solution", "severity_reason", "file", "line"):
            finding.pop(field)
        finding["cwe"] = []
        text = "\n".join(writer_agent.explain_finding(finding)).lower()
        for missing in ("título descriptivo", "descripción del problema",
                        "solución sugerida", "justificación de severidad",
                        "ubicación del hallazgo", "cwe"):
            assert f"dato no disponible: {missing}" in text

    def test_guide_only_has_real_categories(self):
        guide = writer_agent.build_best_practices_guide(sample_result())
        categories = [section["category"] for section in guide["sections"]]
        assert categories == ["A03:2021 - Injection", "A07:2021 - Identification and Authentication Failures"]
        assert guide["sections"][0]["practices"] == ["Usar consultas parametrizadas."]

    def test_no_findings_means_empty_guide_with_honest_note(self):
        guide = writer_agent.build_best_practices_guide(sample_result(findings=[]))
        assert guide["sections"] == []
        assert "no registró hallazgos" in guide["note"]

    def test_category_without_solution_does_not_invent_practices(self):
        findings = [sample_finding(solution=None)]
        guide = writer_agent.build_best_practices_guide(sample_result(findings=findings))
        section = guide["sections"][0]
        assert section["practices"] == []
        assert "no se agregan prácticas" in section["note"]

    def test_data_gaps_list_missing_fields(self):
        result = sample_result(findings=[sample_finding(solution=None, line=None)])
        result["repository"] = {"url": "https://github.com/org/repo", "name": "repo"}
        gaps = writer_agent.collect_data_gaps(result)
        scopes = {(gap["scope"], gap["field"]) for gap in gaps}
        assert ("repository", "commit") in scopes
        assert ("repository", "branch") in scopes
        assert ("finding 1", "solution") in scopes
        assert ("finding 1", "line") in scopes


class TestCompareAnalyses:
    def _base(self):
        return sample_result(findings=[sample_finding()])

    def _target(self):
        return sample_result(findings=[
            sample_finding(),                                    # persistente
            sample_finding(id=9, rule="py-code-injection-eval",  # nuevo
                           file="app/eval.py", line=3, cwe=["CWE-95"]),
        ])

    def test_classifies_new_fixed_persistent(self):
        base = self._base()
        target = self._target()
        base["findings"].append(
            sample_finding(id=5, rule="py-path-traversal", file="app/files.py", line=11, cwe=["CWE-22"]))
        comparison = compare_service.compare_analyses(base, target)
        assert comparison["counts"] == {"new": 1, "fixed": 1, "persistent": 1}
        assert comparison["new"][0]["rule"] == "py-code-injection-eval"
        assert comparison["fixed"][0]["rule"] == "py-path-traversal"
        assert comparison["persistent"][0]["rule"] == "py-sql-injection-concat"
        assert comparison["base"]["commit"] == "abc123def4567890"

    def test_different_repos_raise_valueerror(self):
        other = sample_result()
        other["repository"]["url"] = "https://github.com/other/repo.git"
        with pytest.raises(ValueError):
            compare_service.compare_analyses(self._base(), other)

    def test_missing_url_raises_valueerror(self):
        no_url = sample_result()
        no_url["repository"] = {"name": "repo"}
        with pytest.raises(ValueError):
            compare_service.compare_analyses(self._base(), no_url)

    def test_git_suffix_and_case_do_not_break_same_repo(self):
        target = self._target()
        target["repository"]["url"] = "https://github.com/ORG/Repo.Git/"
        comparison = compare_service.compare_analyses(self._base(), target)
        assert comparison["counts"]["persistent"] == 1


class TestReportEndpoints:
    @pytest.fixture()
    def client(self, monkeypatch):
        from api_server import app
        app.config["TESTING"] = True
        return app.test_client()

    @pytest.fixture()
    def seeded_analysis(self, monkeypatch):
        import api_server
        analysis_id = "99999999-aaaa-bbbb-cccc-dddddddddddd"
        monkeypatch.setitem(api_server.jobs, analysis_id, sample_result(
            analysis_id=analysis_id,
            findings=[sample_finding(id=1)]))
        return analysis_id

    def test_report_md(self, client, seeded_analysis):
        response = client.get(f"/api/analysis/{seeded_analysis}/report.md")
        assert response.status_code == 200
        assert response.content_type.startswith("text/markdown")
        assert "abc123def4567890" in response.get_data(as_text=True)

    def test_report_sarif(self, client, seeded_analysis):
        response = client.get(f"/api/analysis/{seeded_analysis}/report.sarif")
        assert response.status_code == 200
        sarif = response.get_json()
        assert sarif["version"] == "2.1.0"

    def test_executive_summary(self, client, seeded_analysis):
        response = client.get(f"/api/analysis/{seeded_analysis}/executive-summary")
        assert response.status_code == 200
        summary = response.get_json()
        assert summary["repository"]["commit"] == "abc123def4567890"
        assert summary["severity_counts"]["total"] == 1
        assert len(summary["top_findings"]) == 1

    def test_unknown_analysis_is_404(self, client):
        assert client.get("/api/analysis/no-existe/report.md").status_code == 404
        assert client.get("/api/analysis/no-existe/report.sarif").status_code == 404
        assert client.get("/api/analysis/no-existe/executive-summary").status_code == 404

    def test_compare_ok(self, client, monkeypatch):
        import api_server
        base_id = "aaaa0000-0000-0000-0000-000000000001"
        target_id = "aaaa0000-0000-0000-0000-000000000002"
        monkeypatch.setitem(api_server.jobs, base_id, sample_result(
            analysis_id=base_id, findings=[sample_finding()]))
        monkeypatch.setitem(api_server.jobs, target_id, sample_result(
            analysis_id=target_id,
            findings=[sample_finding(), sample_finding(
                id=9, rule="py-code-injection-eval", file="app/eval.py", line=3, cwe=["CWE-95"])]))
        response = client.get(f"/api/analyses/compare?base={base_id}&target={target_id}")
        assert response.status_code == 200
        assert response.get_json()["counts"] == {"new": 1, "fixed": 0, "persistent": 1}

    def test_compare_rejects_distinct_repos(self, client, monkeypatch):
        import api_server
        base_id = "bbbb0000-0000-0000-0000-000000000001"
        target_id = "bbbb0000-0000-0000-0000-000000000002"
        monkeypatch.setitem(api_server.jobs, base_id, sample_result(analysis_id=base_id))
        other = sample_result(analysis_id=target_id)
        other["repository"]["url"] = "https://github.com/other/repo"
        monkeypatch.setitem(api_server.jobs, target_id, other)
        response = client.get(f"/api/analyses/compare?base={base_id}&target={target_id}")
        assert response.status_code == 400

    def test_compare_requires_params_and_existing_analyses(self, client, monkeypatch):
        import api_server
        existing = "cccc0000-0000-0000-0000-000000000001"
        monkeypatch.setitem(api_server.jobs, existing, sample_result(analysis_id=existing))
        assert client.get("/api/analyses/compare").status_code == 400
        assert client.get(
            f"/api/analyses/compare?base={existing}&target=faltante").status_code == 404


class TestExecutiveSummaryContent:
    def test_top_findings_limited_and_sorted(self):
        findings = [sample_finding(id=i, severity="low", line=i, file=f"f{i}.py") for i in range(1, 8)]
        summary = report_builder.build_executive_summary(sample_result(findings=findings))
        assert len(summary["top_findings"]) == report_builder._TOP_FINDINGS_LIMIT
        assert all(f["severity"] == "low" for f in summary["top_findings"])

    def test_summary_declares_gaps_and_note(self):
        result = sample_result()
        result["repository"] = {"url": "https://github.com/org/repo", "name": "repo"}
        summary = report_builder.build_executive_summary(result)
        fields_missing = {(gap["scope"], gap["field"]) for gap in summary["data_gaps"]}
        assert ("repository", "commit") in fields_missing
        assert "datos faltantes" in summary["note"]
