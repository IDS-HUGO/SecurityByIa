"""Pruebas pytest de scanner_tools: detección de stack, adaptadores de las
herramientas opcionales, fusión multi-herramienta y tolerancia a fallos.

Ninguna prueba requiere binarios instalados ni red: los runners se sustituyen
o se les entrega salida JSON pre-armada a los adaptadores (funciones puras).

Ejecución:
    python -m pytest tests/test_scanner_tools.py -v
"""

import json

import pytest

import scanner_tools


def make_stack(**overrides):
    stack = {
        "languages": [], "dependency_files": [], "package_managers": [],
        "requirements_files": [], "package_lock": False,
        "terraform": [], "cloudformation": [], "dockerfiles": [],
        "github_workflows": [], "dependabot": False,
        "has_python": False, "has_node": False,
    }
    stack.update(overrides)
    return stack


@pytest.fixture()
def no_binaries(monkeypatch):
    monkeypatch.setattr(scanner_tools, "_tool_bin", lambda name, env_var: None)


# ---------------------------------------------------------------------------
# Detección de stack
# ---------------------------------------------------------------------------

def test_detect_stack_full(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\n", encoding="utf-8")
    (tmp_path / ".github" / "dependabot.yml").write_text("version: 2\n", encoding="utf-8")
    cfn = tmp_path / "template.yaml"
    cfn.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n", encoding="utf-8")

    stack = scanner_tools.detect_stack(str(tmp_path))
    assert stack["has_python"] is True
    assert stack["package_lock"] is True
    assert "python" in stack["languages"] and "node" in stack["languages"] and "go" in stack["languages"]
    assert "requirements.txt" in stack["requirements_files"]
    assert "package-lock.json" in stack["dependency_files"]
    assert stack["dockerfiles"] == ["Dockerfile"]
    assert stack["terraform"] == ["main.tf"]
    assert stack["cloudformation"] == ["template.yaml"]
    assert stack["github_workflows"] == [".github/workflows/ci.yml"]
    assert stack["dependabot"] is True


def test_detect_stack_empty(tmp_path):
    stack = scanner_tools.detect_stack(str(tmp_path))
    assert stack["languages"] == []
    assert stack["dependency_files"] == []
    assert stack["dependabot"] is False
    assert stack["has_python"] is False


# ---------------------------------------------------------------------------
# Adaptadores: formato de hallazgo idéntico al de analyzer.py
# ---------------------------------------------------------------------------

def test_trufflehog_finding_marks_verification_and_redacts_secret():
    raw = {
        "DetectorName": "AWSAccessKey",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLESECRETVALUE",
        "SourceMetadata": {"Data": {"File": "/tmp/repo/config/settings.py", "Line": 12}},
    }
    finding = scanner_tools._finding_from_trufflehog(raw, "/tmp/repo")
    assert finding["tools"] == ["trufflehog"]
    assert finding["verification"] == "valid"
    assert finding["severity"] == "critical"
    assert finding["file"] == "config/settings.py"
    assert finding["line"] == 12
    assert finding["cwe"] == ["CWE-798"]
    assert "AKIAIOSFODNN7EXAMPLESECRETVALUE" not in json.dumps(finding), "el valor del secreto nunca se guarda"


def test_trufflehog_invalid_secret_is_medium():
    raw = {"DetectorName": "GitlabPAT", "Verified": False,
           "SourceMetadata": {"Data": {"File": "/tmp/repo/x.env", "Line": 3}}}
    finding = scanner_tools._finding_from_trufflehog(raw, "/tmp/repo")
    assert finding["verification"] == "invalid"
    assert finding["severity"] == "medium"


def test_bandit_finding_uses_reported_cwe():
    raw = {
        "test_id": "B608", "test_name": "hardcoded_sql_expressions",
        "issue_severity": "MEDIUM", "issue_text": "Possible SQL injection vector",
        "issue_cwe": {"id": 89},
        "filename": "/tmp/repo/src/db.py", "line_number": 40,
    }
    finding = scanner_tools._finding_from_bandit(raw, "/tmp/repo")
    assert finding["tools"] == ["bandit"]
    assert finding["cwe"] == ["CWE-89"]
    assert finding["severity"] == "medium"
    assert finding["file"] == "src/db.py"
    assert finding["line"] == 40


def test_osv_finding_keeps_package_and_reference():
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "SQL injection in helper",
        "aliases": ["CVE-2024-1234"],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-89"]},
    }
    finding = scanner_tools._finding_from_osv(vuln, "requests", "2.19.0", "PyPI", "/tmp/repo/requirements.txt", "/tmp/repo")
    assert finding["rule"] == "osv-scanner/requests/GHSA-xxxx-yyyy-zzzz"
    assert finding["severity"] == "high"
    assert finding["file"] == "requirements.txt"
    assert finding["line"] is None
    assert finding["cwe"] == ["CWE-89"]
    assert finding["package"]["name"] == "requests"
    assert "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz" in finding["references"]


def test_hadolint_root_user_maps_to_cwe_250():
    item = {"code": "DL3002", "severity": "warning", "message": "Last USER should not be root",
            "file": "Dockerfile", "line": 5}
    finding = scanner_tools._finding_from_hadolint(item, "/tmp/repo")
    assert finding["rule"] == "hadolint/DL3002"
    assert finding["cwe"] == ["CWE-250"]
    assert finding["severity"] == "medium"


def test_npm_audit_finding_uses_via_cwes():
    block = {
        "severity": "moderate", "range": "<1.2.3",
        "via": [{"title": "Regular Expression Denial of Service", "url": "https://github.com/advisories/GHSA-1",
                 "cwes": ["CWE-400"]}],
        "fixAvailable": {"name": "minimatch", "version": "1.2.4", "isSemVerMajor": True},
    }
    # _run_npm_audit construye el hallazgo en línea; probamos el mapeo vía el runner con stdout falso.
    import subprocess

    class FakeCompleted:
        stdout = json.dumps({"vulnerabilities": {"minimatch": block}})
        returncode = 0

    def fake_run(cmd, **kwargs):
        return FakeCompleted()

    import scanner_tools as st
    original = st.subprocess.run
    orig_bin = st._tool_bin
    st.subprocess.run = fake_run
    st._tool_bin = lambda name, env: "/usr/bin/npm"
    try:
        findings, status = st._run_npm_audit("/tmp/repo", 60)
    finally:
        st.subprocess.run = original
        st._tool_bin = orig_bin
    assert status == "completed"
    finding = findings[0]
    assert finding["tools"] == ["npm-audit"]
    assert finding["severity"] == "medium"
    assert finding["cwe"] == ["CWE-400"]
    assert "1.2.4" in finding["solution"]


# ---------------------------------------------------------------------------
# Fusión multi-herramienta
# ---------------------------------------------------------------------------

def test_merge_unions_tools_and_keeps_highest_severity():
    semgrep = scanner_tools._make_finding(
        "semgrep", "py-command-injection", "medium", "app.py", 10,
        "title", "problem", "solution", cwe=["CWE-78: Injection"], owasp=scanner_tools.OWASP_INJECTION)
    bandit = scanner_tools._make_finding(
        "bandit", "bandit/B602", "high", "app.py", 11,
        "title2", "problem2", "solution2", cwe=["CWE-78"])
    merged = scanner_tools.merge_tool_findings([semgrep, bandit])
    assert len(merged) == 1
    assert merged[0]["tools"] == ["semgrep", "bandit"]
    assert merged[0]["severity"] == "high"
    assert merged[0]["rule"] == "py-command-injection"  # gana el motor primario
    assert merged[0]["id"] == 1


def test_merge_keeps_verification_flag():
    gitleaks = scanner_tools._make_finding(
        "gitleaks", "gitleaks/aws-key", "critical", "conf.py", 5,
        "t", "p", "s", cwe=["CWE-798"])
    trufflehog = scanner_tools._make_finding(
        "trufflehog", "trufflehog/AmazonWebServicesKey", "high", "conf.py", 6,
        "t2", "p2", "s2", cwe=["CWE-798"], extra={"verification": "valid"})
    merged = scanner_tools.merge_tool_findings([gitleaks, trufflehog])
    assert len(merged) == 1
    assert merged[0]["tools"] == ["gitleaks", "trufflehog"]
    assert merged[0]["verification"] == "valid"


def test_merge_does_not_mix_different_packages():
    a = scanner_tools._finding_from_osv({"id": "GHSA-1", "summary": "s1"}, "pkg-a", "1.0", "PyPI", "/r/requirements.txt", "/r")
    b = scanner_tools._finding_from_osv({"id": "GHSA-2", "summary": "s2"}, "pkg-b", "2.0", "PyPI", "/r/requirements.txt", "/r")
    merged = scanner_tools.merge_tool_findings([a, b])
    assert len(merged) == 2


# ---------------------------------------------------------------------------
# Orquestación: sin binarios, sin romper; saltos por stack
# ---------------------------------------------------------------------------

def test_run_tools_reports_unavailable_without_binaries(tmp_path, no_binaries):
    report = scanner_tools.run_tools(str(tmp_path), stack=make_stack(has_python=True))
    tools = report["tools"]
    assert tools["osv-scanner"] == "skipped"
    assert tools["bandit"] == "unavailable"
    assert tools["trufflehog"] == "unavailable"
    assert tools["checkov"] == "skipped" and tools["trivy"] == "skipped"
    assert tools["hadolint"] == "skipped"
    assert tools["zizmor"] == "skipped"
    assert tools["syft"] == "skipped"
    assert tools["scancode"] == "skipped"
    assert tools["scorecard"] == "skipped"
    assert tools["deptry"] == "skipped"
    assert tools["dependabot"] == "missing"
    assert any(f["rule"] == "dependabot/missing-config" for f in report["findings"])
    assert report["sbom"] is None and report["licenses"] is None


def test_run_tools_unavailable_for_applicable_iac(tmp_path, no_binaries):
    report = scanner_tools.run_tools(
        str(tmp_path), stack=make_stack(terraform=["main.tf"], dockerfiles=["Dockerfile"]))
    assert report["tools"]["checkov"] == "unavailable"
    assert report["tools"]["trivy"] == "unavailable"
    assert report["tools"]["hadolint"] == "unavailable"


def test_run_tools_never_raises_on_runner_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_tools, "_tool_bin", lambda name, env_var: "/fake/bin")

    def broken_runner(root, timeout):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner_tools, "_run_bandit", broken_runner)
    report = scanner_tools.run_tools(
        str(tmp_path), stack=make_stack(has_python=True, dependency_files=["requirements.txt"]))
    assert report["tools"]["bandit"] == "error"
    assert report["tools"]["osv-scanner"] == "unavailable"  # binario falso no ejecutable no rompe
    assert "dependabot/missing-config" in [f["rule"] for f in report["findings"]]


def test_run_tools_skips_depcheck_without_lockfile(tmp_path, no_binaries):
    report = scanner_tools.run_tools(str(tmp_path), stack=make_stack(has_node=True))
    assert report["tools"]["depcheck"] == "skipped"
    assert report["tools"]["npm-audit"] == "skipped"
