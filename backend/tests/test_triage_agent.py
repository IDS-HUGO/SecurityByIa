"""Tests for AI Triage Agent (Feature 5).

Covers:
- Bounded 20-line excerpt extraction with strict secret redaction.
- Negative examples heuristics from controls inventory:
  1. Plain-text Jinja2 templates (only discarded if NOT inserted as HTML).
  2. Docker image tags/digests mistakenly flagged as secrets.
  3. SSRF in client-side / browser code.
  4. Migration scripts with fixed paths.
  5. Test JWTs and mock credentials in test directories.
  6. Invalid secrets from scanners are NOT discarded in bulk.
- Strict schema validation & fail-open fallback to 'incierto'.
- Opt-in enforcement (no external triage unless explicitly enabled).
- Human decision registration, mandatory reason validation, and persistent fingerprint suppression.
- Flask API endpoints (POST triage, GET review-queue, GET fingerprints).
- Multi-model triage benchmark (Gemini vs OpenAI vs Claude) FPR before/after.
"""

import json
import os
import tempfile
from pathlib import Path
import pytest

import triage_agent
from api_server import app, jobs, jobs_lock, STORAGE


@pytest.fixture
def test_env_dir():
    temp_dir = tempfile.mkdtemp(prefix="test-triage-")
    yield Path(temp_dir)
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolate_fingerprints():
    fp_path = triage_agent._FINGERPRINTS_FILE
    original_data = None
    if fp_path.is_file():
        original_data = fp_path.read_text(encoding="utf-8")
    yield
    if original_data is not None:
        fp_path.write_text(original_data, encoding="utf-8")
    elif fp_path.is_file():
        fp_path.unlink()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# -----------------------------------------------------------------------------
# 1. Bounded Context & Secret Redaction
# -----------------------------------------------------------------------------

def test_secret_redaction_removes_sensitive_credentials():
    raw_text = (
        'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
        'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\n'
        'const auth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this";\n'
        'const password = "super_secret_master_password_999";\n'
    )
    redacted = triage_agent.redact_secrets_in_text(raw_text, extra_secrets=["super_secret_master_password_999"])
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "do_not_leak_this" not in redacted
    assert "super_secret_master_password_999" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_extract_20_line_context_clamps_and_centers(test_env_dir):
    sample_file = test_env_dir / "sample.py"
    lines = [f"line_{i} = {i}\n" for i in range(1, 51)]
    lines[24] = 'secret_key = "AKIAIOSFODNN7EXAMPLE"\n'  # Line 25
    sample_file.write_text("".join(lines), encoding="utf-8")

    ctx_lines, raw_excerpt = triage_agent.extract_20_line_context(
        str(sample_file),
        target_line=25,
        root_dir=str(test_env_dir),
    )

    assert len(ctx_lines) == 20
    assert ctx_lines[0]["line"] == 15
    assert ctx_lines[-1]["line"] == 34
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_excerpt
    assert "[REDACTED_SECRET]" in raw_excerpt


# -----------------------------------------------------------------------------
# 2. Schema Validation & Fail-Open
# -----------------------------------------------------------------------------

def test_validate_triage_response_valid_cases():
    valid_tp = {"verdict": "verdadero", "confidence": 0.95, "reason": "Inyección SQL directa sin parámetros."}
    ok, verdict, conf, reason = triage_agent.validate_triage_response(valid_tp)
    assert ok is True
    assert verdict == "verdadero"
    assert conf == 0.95
    assert "Inyección SQL" in reason

    valid_fp = {"verdict": "falso", "confidence": "90%", "reason": "Ruta estática en migración interna."}
    ok, verdict, conf, reason = triage_agent.validate_triage_response(valid_fp)
    assert ok is True
    assert verdict == "falso"
    assert conf == 0.90


def test_validate_triage_response_rejects_invalid_schema():
    # Bad verdict
    ok, verdict, conf, reason = triage_agent.validate_triage_response({"verdict": "quizas", "confidence": 0.5, "reason": "algo"})
    assert ok is False
    assert verdict == "incierto"

    # Missing reason
    ok, verdict, conf, reason = triage_agent.validate_triage_response({"verdict": "verdadero", "confidence": 0.8, "reason": ""})
    assert ok is False
    assert verdict == "incierto"

    # Non-dictionary
    ok, verdict, conf, reason = triage_agent.validate_triage_response("not-json")
    assert ok is False
    assert verdict == "incierto"


# -----------------------------------------------------------------------------
# 3. Deterministic Negative Examples from Controls Inventory
# -----------------------------------------------------------------------------

def test_heuristic_plain_text_jinja2_is_false_positive():
    finding = {"rule": "python.flask.security.jinja2-autoescape", "file": "templates/email_notice.txt"}
    context = "from jinja2 import Template\nt = Template('Hello {{ name }}', autoescape=False)\nemail_text = t.render(name=user)"
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "falso"
    assert "texto plano" in reason


def test_heuristic_jinja2_rendered_in_html_is_true_positive():
    finding = {"rule": "python.flask.security.jinja2-autoescape", "file": "views/dashboard.py"}
    context = "from jinja2 import Environment\nenv = Environment(autoescape=False)\nreturn render_template('dashboard.html', env=env)"
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "verdadero"
    assert "HTML" in reason


def test_heuristic_docker_digest_flagged_as_secret_is_false_positive():
    finding = {"rule": "generic-api-key", "file": "Dockerfile"}
    context = "FROM node:18-alpine@sha256:d8262a0437435f118ae260ca3eb70a831e50f5885deaa1259e2b10900ccb4f0b\nWORKDIR /app"
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "falso"
    assert "Docker" in reason


def test_heuristic_browser_client_code_is_not_ssrf():
    finding = {"rule": "security.ssrf.axios-fetch", "file": "frontend/src/api/client.js", "cwe": ["CWE-918"]}
    context = "export async function getProfile(id) { return fetch('/api/user/' + id); }"
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "falso"
    assert "navegador" in reason


def test_heuristic_database_migration_with_static_paths_is_false_positive():
    finding = {"rule": "python.lang.security.path-traversal", "file": "migrations/versions/001_initial.py", "cwe": ["CWE-22"]}
    context = "with open('migrations/schema.sql', 'r') as f:\n    db.execute(f.read())"
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "falso"
    assert "migración" in reason


def test_heuristic_test_credential_in_tests_folder_is_false_positive():
    finding = {"rule": "gitleaks-jwt-secret", "file": "tests/fixtures/mock_auth.py"}
    context = 'MOCK_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."'
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    assert result is not None
    verdict, conf, reason = result
    assert verdict == "falso"
    assert "pruebas" in reason


def test_invalid_secrets_are_not_discarded_in_bulk():
    """Scanner marked a secret as 'INVALID', but triage agent must NOT discard it in bulk."""
    finding = {
        "rule": "trufflehog-github-pat",
        "file": "backend/legacy_config.py",
        "verification": "INVALID",
        "secret": "ghp_expired1234567890abcdefghijklmnopqr",
    }
    context = 'GITHUB_TOKEN = "ghp_expired1234567890abcdefghijklmnopqr"'
    result = triage_agent.evaluate_finding_heuristics(finding, context)
    # Does not discard in bulk; returns None so it goes through full model triage or human review
    assert result is None


# -----------------------------------------------------------------------------
# 4. Opt-in Enforcement & Fingerprint Suppression
# -----------------------------------------------------------------------------

def test_triage_agent_defaults_to_rule_when_opt_in_disabled(test_env_dir):
    sample_file = test_env_dir / "index.js"
    sample_file.write_text("console.log('hello');", encoding="utf-8")

    findings = [{
        "id": 1,
        "rule": "javascript.lang.security.audit.path-traversal",
        "file": "index.js",
        "line": 1,
        "severity": "high",
    }]

    # When enable_ai_triage is False
    triage_agent.run_triage_on_findings(
        findings,
        str(test_env_dir),
        enable_ai_triage=False,
    )

    triage_res = findings[0].get("triage", {})
    assert triage_res.get("decided_by") == "regla"
    assert triage_res.get("verdict") == "verdadero"


def test_save_and_match_false_positive_fingerprint(test_env_dir):
    file_path = "backend/config/routes.py"
    rule = "python.lang.security.deserialization"
    snippet = "import pickle\ndata = pickle.loads(STATIC_SAFE_PAYLOAD)"

    fp = triage_agent.save_false_positive_fingerprint(
        file_path=file_path,
        rule=rule,
        code_snippet=snippet,
        reason="Carga de configuración interna empaquetada en build time",
        author="alice-sec",
    )
    assert len(fp) == 64  # SHA256 length

    test_finding = {
        "file": file_path,
        "rule": rule,
        "code_context": [{"line": 10, "text": snippet}],
    }

    matched = triage_agent.match_known_false_positive(test_finding)
    assert matched is not None
    assert matched["author"] == "alice-sec"
    assert matched["fingerprint"] == fp

    # Run triage on this finding: should be automatically suppressed
    findings = [test_finding]
    triage_agent.run_triage_on_findings(findings, str(test_env_dir), enable_ai_triage=True)
    assert test_finding.get("false_positive") is True
    assert test_finding.get("status") == "false_positive"
    assert test_finding.get("triage", {}).get("decided_by") == "persona"
    assert "alice-sec" in test_finding.get("triage", {}).get("reason")


# -----------------------------------------------------------------------------
# 5. Flask API Triage Endpoints
# -----------------------------------------------------------------------------

def test_api_triage_endpoints(client, test_env_dir):
    analysis_id = "test-analysis-f5-123"
    test_analysis = {
        "analysis_id": analysis_id,
        "status": "completed",
        "findings": [
            {
                "id": 1,
                "rule": "generic.sql.injection",
                "file": "models/user.py",
                "line": 14,
                "severity": "critical",
                "problem": "Raw query interpolation",
                "solution": "Use parameterized query",
                "triage": {"verdict": "incierto", "decided_by": "agente"},
            },
            {
                "id": 2,
                "rule": "hardcoded.credential",
                "file": "tests/test_login.py",
                "line": 5,
                "severity": "medium",
                "triage": {"verdict": "incierto", "decided_by": "agente"},
            },
        ],
    }

    with jobs_lock:
        jobs[analysis_id] = test_analysis

    # 1. Test GET /api/analysis/<id>/review-queue (ordered by severity)
    rq_res = client.get(f"/api/analysis/{analysis_id}/review-queue")
    assert rq_res.status_code == 200
    rq_data = rq_res.get_json()
    assert rq_data["total"] == 2
    # Critical must precede Medium
    assert rq_data["queue"][0]["id"] == 1
    assert rq_data["queue"][1]["id"] == 2

    # 2. Test POST /api/analysis/<id>/finding/<id>/triage with missing reason (must return 400)
    bad_req = client.post(
        f"/api/analysis/{analysis_id}/finding/1/triage",
        json={"decision": "verdadero", "reason": ""},
    )
    assert bad_req.status_code == 400
    assert "El motivo es obligatorio" in bad_req.get_json().get("error", "")

    # 3. Test POST triage confirming finding 1
    confirm_res = client.post(
        f"/api/analysis/{analysis_id}/finding/1/triage",
        json={
            "decision": "verdadero",
            "reason": "Confirmado en revisión de código: falta sanitización.",
            "author": "analista-seguridad",
        },
    )
    assert confirm_res.status_code == 200
    confirmed_data = confirm_res.get_json()
    assert confirmed_data["status"] == "success"
    assert confirmed_data["finding"]["triage"]["verdict"] == "verdadero"
    assert confirmed_data["finding"]["triage"]["decided_by"] == "persona"

    # 4. Test POST triage marking finding 2 as false positive (must generate fingerprint)
    fp_res = client.post(
        f"/api/analysis/{analysis_id}/finding/2/triage",
        json={
            "decision": "falso",
            "reason": "Es un mock en la carpeta tests/.",
            "author": "bob-security",
        },
    )
    assert fp_res.status_code == 200
    fp_data = fp_res.get_json()
    assert fp_data["finding"]["false_positive"] is True
    assert fp_data["fingerprint"] is not None

    # 5. Check GET /api/triage/fingerprints returns the stored fingerprint
    fps_res = client.get("/api/triage/fingerprints")
    assert fps_res.status_code == 200
    assert fp_data["fingerprint"] in fps_res.get_json()


# -----------------------------------------------------------------------------
# 6. Multi-Model Benchmark Comparison
# -----------------------------------------------------------------------------

def test_multi_model_triage_benchmark_comparison():
    detected_findings = [
        {"id": 1, "matched": True},
        {"id": 2, "matched": True},
        {"id": 3, "matched": False},
        {"id": 4, "matched": False},
        {"id": 5, "matched": False},
    ]
    raw_fpr = 0.60
    bench_result = triage_agent.evaluate_multi_model_triage_benchmark(detected_findings, raw_fpr=raw_fpr)

    assert bench_result["raw_fpr_before"] == 0.60
    models = bench_result["models_evaluated"]
    assert len(models) >= 2  # Gemini vs OpenAI or Claude

    model_names = [m["provider"] for m in models]
    assert "gemini" in model_names
    assert "openai" in model_names or "claude" in model_names

    for m in models:
        assert m["fpr_after"] < m["fpr_before"]
        assert m["delta_fpr_pts"] < 0
        assert m["false_positives_eliminated"] > 0
        assert m["true_positives_retained"] == 2
        assert m["standardized_prompt"].startswith("TRIAGE_SYSTEM_PROMPT")
