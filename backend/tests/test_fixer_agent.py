"""Test suite for Feature 6 (F6: Corrección asistida con verificación).

Validates:
- Deterministic code templates for secure patterns:
  * yaml.load -> yaml.safe_load
  * verify=False -> verify=True
  * updating dependency in requirements.txt and package.json
  * DEBUG = True -> DEBUG = False
  * shell=True -> shell=False
- Minimal unified diff generation.
- Isolated temporary branch verification (never pushing to main):
  * Verified when finding is resolved without new alerts.
  * Discarded when finding persists or introduces new alerts.
- Analyzed project tests sandbox (opt-in + own repo + docker --network none).
- Human review workflow (approve / reject with mandatory reason).
- Flask API endpoints (/fix, /remediation/review, /tests/run).
- Markdown report remediation section and summary counts.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import pytest

from api_server import app, jobs, STORAGE
import fixer_agent
from analyzer import _deduplicate, _markdown


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# -----------------------------------------------------------------------------
# 1. Deterministic Templates Tests
# -----------------------------------------------------------------------------

def test_template_yaml_safe_load():
    unsafe_code = (
        "import yaml\n"
        "data = yaml.load(user_input, Loader=yaml.Loader)\n"
        "print(data)\n"
    )
    res = fixer_agent.fix_yaml_load_pattern(unsafe_code)
    assert res is not None
    patched, explanation = res
    assert "yaml.safe_load(user_input)" in patched
    assert "CWE-502" in explanation

    # Pattern without Loader
    unsafe_simple = "obj = yaml.load(stream)\n"
    res_simple = fixer_agent.fix_yaml_load_pattern(unsafe_simple)
    assert res_simple is not None
    assert "yaml.safe_load(stream)" in res_simple[0]


def test_template_verify_false_tls():
    unsafe_req = "response = requests.get('https://example.com/api', verify=False, timeout=10)\n"
    res = fixer_agent.fix_verify_false_pattern(unsafe_req)
    assert res is not None
    patched, explanation = res
    assert "verify=True" in patched
    assert "verify=False" not in patched
    assert "CWE-295" in explanation


def test_template_dependency_update_requirements():
    reqs = (
        "flask==2.0.1\n"
        "requests==2.20.0\n"
        "jinja2>=2.10\n"
    )
    res = fixer_agent.fix_dependency_update_pattern(
        content=reqs,
        file_path="requirements.txt",
        package_name="requests",
        fixed_version="2.31.0",
    )
    assert res is not None
    patched, explanation = res
    assert "requests==2.31.0" in patched
    assert "flask==2.0.1" in patched
    assert "2.31.0" in explanation


def test_template_dependency_update_package_json():
    pkg_json = json.dumps({
        "name": "my-app",
        "dependencies": {
            "express": "^4.16.0",
            "lodash": "4.17.15"
        }
    }, indent=2)
    res = fixer_agent.fix_dependency_update_pattern(
        content=pkg_json,
        file_path="package.json",
        package_name="lodash",
        fixed_version="4.17.21",
    )
    assert res is not None
    patched, explanation = res
    assert '"lodash": "^4.17.21"' in patched
    assert "4.17.21" in explanation


def test_template_debug_true():
    code = "DEBUG = True\nSECRET_KEY = 'secret'\n"
    res = fixer_agent.fix_debug_true_pattern(code)
    assert res is not None
    patched, explanation = res
    assert "DEBUG = False" in patched
    assert "CWE-489" in explanation


def test_template_subprocess_shell_true():
    code = "subprocess.run(cmd, shell=True, check=True)\n"
    res = fixer_agent.fix_subprocess_shell_true_pattern(code)
    assert res is not None
    patched, explanation = res
    assert "shell=False" in patched
    assert "CWE-78" in explanation


# -----------------------------------------------------------------------------
# 2. Unified Diff Generation
# -----------------------------------------------------------------------------

def test_unified_diff_format():
    orig = "def run():\n    return False\n"
    patched = "def run():\n    return True\n"
    diff = fixer_agent.generate_unified_diff(orig, patched, "app/main.py")
    assert "--- a/app/main.py" in diff
    assert "+++ b/app/main.py" in diff
    assert "-    return False" in diff
    assert "+    return True" in diff


# -----------------------------------------------------------------------------
# 3. Patch Verification Loop on Isolated Temporary Branch
# -----------------------------------------------------------------------------

def test_verify_and_apply_patch_success(monkeypatch):
    temp_dir = tempfile.mkdtemp(prefix="test-fixer-git-")
    try:
        # Initialize a git repo
        subprocess.run(["git", "init"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_dir, check=True)

        target_file = Path(temp_dir) / "service.py"
        target_file.write_text("import yaml\nyaml.load(data, Loader=yaml.Loader)\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=temp_dir, check=True)

        finding = {
            "id": 1,
            "rule": "python.lang.security.insecure-yaml-load",
            "file": "service.py",
            "line": 2,
        }
        patch = fixer_agent.create_patch_for_finding(finding, temp_dir)
        assert patch is not None

        # Mock Semgrep to report finding resolved and no new findings
        monkeypatch.setattr(
            fixer_agent,
            "_check_semgrep_on_file",
            lambda root, fpath, rule: (True, []),
        )

        res = fixer_agent.verify_and_apply_patch(temp_dir, finding, patch)
        assert res["verified"] is True
        assert res["status"] == "verified"
        assert "exitosamente" in res["verification"]["message"]

        # Ensure working tree was reverted to original commit and no branch remains
        current_branch = subprocess.run(
            ["git", "-C", temp_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        assert current_branch in ("master", "main")
        assert "yaml.load(data, Loader=yaml.Loader)" in target_file.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_verify_and_apply_patch_discarded_when_finding_persists(monkeypatch):
    temp_dir = tempfile.mkdtemp(prefix="test-fixer-fail-")
    try:
        subprocess.run(["git", "init"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_dir, check=True)

        target_file = Path(temp_dir) / "api.py"
        target_file.write_text("DEBUG = True\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=temp_dir, check=True)

        finding = {"id": 1, "rule": "python.flask.debug-mode", "file": "api.py", "line": 1}
        patch = fixer_agent.create_patch_for_finding(finding, temp_dir)

        # Mock Semgrep reporting finding NOT resolved
        monkeypatch.setattr(
            fixer_agent,
            "_check_semgrep_on_file",
            lambda root, fpath, rule: (False, []),
        )

        res = fixer_agent.verify_and_apply_patch(temp_dir, finding, patch)
        assert res["verified"] is False
        assert res["status"] == "discarded"
        assert "persiste" in res["verification"]["message"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_verify_and_apply_patch_discarded_when_new_finding_introduced(monkeypatch):
    temp_dir = tempfile.mkdtemp(prefix="test-fixer-new-")
    try:
        subprocess.run(["git", "init"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_dir, check=True)

        target_file = Path(temp_dir) / "client.py"
        target_file.write_text("requests.get(url, verify=False)\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=temp_dir, check=True)

        finding = {"id": 1, "rule": "python.requests.tls-verify-false", "file": "client.py", "line": 1}
        patch = fixer_agent.create_patch_for_finding(finding, temp_dir)

        # Mock Semgrep reporting original resolved but new finding introduced
        monkeypatch.setattr(
            fixer_agent,
            "_check_semgrep_on_file",
            lambda root, fpath, rule: (True, [{"rule": "new.finding.rule", "message": "New alert"}]),
        )

        res = fixer_agent.verify_and_apply_patch(temp_dir, finding, patch)
        assert res["verified"] is False
        assert res["status"] == "discarded"
        assert "nuevos hallazgos" in res["verification"]["message"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_fixer_never_pushes_to_main(monkeypatch):
    """Safety check: git push must never be called."""
    called_cmds = []

    def fake_run(cmd, *args, **kwargs):
        called_cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        fixer_agent,
        "_check_semgrep_on_file",
        lambda root, fpath, rule: (True, []),
    )

    finding = {"id": 1, "file": "dummy.py", "rule": "test"}
    patch = {"file": "dummy.py", "diff": "--- a/dummy.py\n+++ b/dummy.py\n", "patched_code": "new"}
    fixer_agent.verify_and_apply_patch("/tmp", finding, patch)

    for cmd in called_cmds:
        assert "push" not in cmd, f"Git push command was detected: {cmd}"


# -----------------------------------------------------------------------------
# 4. Project Tests Sandbox Isolation
# -----------------------------------------------------------------------------

def test_sandbox_requires_opt_in_and_own_repo():
    # Without opt-in
    res1 = fixer_agent.run_project_tests_in_sandbox("/tmp", opt_in=False, is_own_repo=True)
    assert res1["executed"] is False
    assert res1["status"] == "skipped"

    # Without own_repo
    res2 = fixer_agent.run_project_tests_in_sandbox("/tmp", opt_in=True, is_own_repo=False)
    assert res2["executed"] is False
    assert res2["status"] == "skipped"


def test_sandbox_docker_command_has_no_network(monkeypatch):
    executed_cmds = []

    def fake_which(bin_name):
        return "/usr/bin/docker" if bin_name == "docker" else None

    def fake_run(cmd, *args, **kwargs):
        executed_cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    res = fixer_agent.run_project_tests_in_sandbox("/tmp/repo", opt_in=True, is_own_repo=True)
    assert res["executed"] is True
    assert res["status"] == "passed"
    assert res["network_disabled"] is True

    # Assert --network none was passed to docker
    assert len(executed_cmds) == 1
    cmd = executed_cmds[0]
    assert "docker" in cmd[0]
    assert "--network" in cmd
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "none"


# -----------------------------------------------------------------------------
# 5. Human Review Workflow
# -----------------------------------------------------------------------------

def test_record_human_remediation_review_approval():
    finding = {"id": 1, "remediation": {"status": "verified"}}
    fixer_agent.record_human_remediation_review(
        finding,
        decision="approved",
        reason="Parche revisado y verificado en entorno de staging.",
        author="qa-engineer",
    )
    rem = finding["remediation"]
    assert rem["status"] == "approved"
    assert rem["review_decision"] == "approved"
    assert rem["reviewer"] == "qa-engineer"
    assert "staging" in rem["review_reason"]


def test_record_human_remediation_review_rejection_mandatory_reason():
    finding = {"id": 1, "remediation": {"status": "verified"}}
    # Rejection with valid reason
    fixer_agent.record_human_remediation_review(
        finding,
        decision="rejected",
        reason="Requiere refactorización adicional en la arquitectura.",
        author="security-lead",
    )
    assert finding["remediation"]["status"] == "rejected"

    # Empty reason must raise ValueError
    with pytest.raises(ValueError, match="El motivo es obligatorio"):
        fixer_agent.record_human_remediation_review(
            finding,
            decision="approved",
            reason="",
        )


# -----------------------------------------------------------------------------
# 6. API Server Endpoints (/fix, /remediation/review, /tests/run)
# -----------------------------------------------------------------------------

def test_api_propose_and_verify_fix_endpoint(client):
    analysis_id = "test-analysis-f6-fix"
    finding = {
        "id": 1,
        "title": "Unsafe YAML deserialization",
        "rule": "yaml.load",
        "file": "app.py",
        "code_context": [{"line": 1, "text": "yaml.load(payload)"}],
        "remediation": {"status": "open", "diff": None},
    }
    sample_analysis = {
        "analysis_id": analysis_id,
        "status": "completed",
        "stage": "completed",
        "findings": [finding],
        "created_at": "2026-10-14T10:00:00Z",
    }
    jobs[analysis_id] = sample_analysis

    res = client.post(f"/api/analysis/{analysis_id}/finding/1/fix")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["remediation"]["status"] in ("verified", "patch_proposed")
    assert "diff" in data["remediation"]
    assert "yaml.safe_load" in data["remediation"]["diff"]


def test_api_review_remediation_endpoint(client):
    analysis_id = "test-analysis-f6-review"
    finding = {
        "id": 2,
        "title": "TLS verification disabled",
        "rule": "tls.verify",
        "file": "client.py",
        "remediation": {"status": "verified", "diff": "--- a/client.py\n+++ b/client.py\n"},
    }
    sample_analysis = {
        "analysis_id": analysis_id,
        "status": "completed",
        "stage": "completed",
        "findings": [finding],
        "created_at": "2026-10-14T10:00:00Z",
    }
    jobs[analysis_id] = sample_analysis

    # Missing reason -> 400
    res_bad = client.post(
        f"/api/analysis/{analysis_id}/finding/2/remediation/review",
        json={"decision": "approved", "reason": ""},
    )
    assert res_bad.status_code == 400
    assert "motivo es obligatorio" in res_bad.get_json()["error"]

    # Valid approval
    res_ok = client.post(
        f"/api/analysis/{analysis_id}/finding/2/remediation/review",
        json={"decision": "approved", "reason": "Cambio seguro sin impacto en clientes.", "author": "ciso"},
    )
    assert res_ok.status_code == 200
    data = res_ok.get_json()
    assert data["finding"]["remediation"]["status"] == "approved"
    assert data["finding"]["remediation"]["reviewer"] == "ciso"


def test_api_run_sandbox_tests_endpoint(client):
    analysis_id = "test-analysis-f6-tests"

    # Forbidden without opt-in
    res_forbidden = client.post(
        f"/api/analysis/{analysis_id}/tests/run",
        json={"opt_in": False, "is_own_repo": True},
    )
    assert res_forbidden.status_code == 403

    # Forbidden without own repo
    res_forbidden2 = client.post(
        f"/api/analysis/{analysis_id}/tests/run",
        json={"opt_in": True, "is_own_repo": False},
    )
    assert res_forbidden2.status_code == 403


# -----------------------------------------------------------------------------
# 7. Deduplication, Markdown Report & Remediation Summary Integration
# -----------------------------------------------------------------------------

def test_deduplicate_initializes_remediation():
    raw_findings = [
        {"file": "app.py", "line": 10, "cwe": "CWE-89", "rule": "sql-injection"},
    ]
    deduped = _deduplicate(raw_findings)
    assert len(deduped) == 1
    rem = deduped[0].get("remediation")
    assert rem is not None
    assert rem["status"] == "open"
    assert rem["diff"] is None
    assert rem["touched_files"] == ["app.py"]


def test_markdown_report_includes_remediation_summary():
    findings = [
        {
            "id": 1,
            "title": "Insecure YAML load",
            "severity": "high",
            "rule": "yaml.load",
            "owasp": "A08:2021",
            "cwe": "CWE-502",
            "file": "app.py",
            "line": 15,
            "problem": "Arbitrary code execution",
            "solution": "Use yaml.safe_load",
            "remediation": {
                "status": "verified",
                "diff": "--- a/app.py\n+++ b/app.py\n- yaml.load(f)\n+ yaml.safe_load(f)",
            },
        },
        {
            "id": 2,
            "title": "Exposed API key",
            "severity": "critical",
            "rule": "gitleaks.generic-api-key",
            "owasp": "A07:2021",
            "cwe": "CWE-798",
            "file": "secrets.py",
            "line": 3,
            "problem": "Exposed key in code",
            "solution": "Store in environment variable",
            "remediation": {"status": "open", "diff": None},
        },
    ]
    md = _markdown(findings, "https://github.com/example/repo")
    assert "- **Remediation Status:** verified" in md
    assert "- **Proposed Fix:**" in md
    assert "yaml.safe_load" in md
    assert "## Remediation Summary (Feature 6)" in md
    assert "- Verified: **1**" in md
    assert "- Open: **1**" in md
