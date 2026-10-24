"""Tests for Feature 3 and Feature 4:
- F3: Multi-tool coverage, OSV CVSS scoring, package metadata, tool/pair benchmark evaluations,
      and deduplication by (file, line, cwe) with path existence checks.
- F4: Context-aware severity engine with controls inventory, OWASP 2021 mapping fallback,
      remediation deadlines (Control 6), AI 1-level severity adjustment guard,
      and 30 hand-labeled verification findings test reporting exact match rate.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

import analyzer
import benchmark_service
import scanner_tools
import severity_engine


# ==============================================================================
# F4: 30 Hand-Labeled Security Findings Severity Verification
# ==============================================================================

HAND_LABELED_30_FINDINGS: List[Dict[str, Any]] = [
    # 1. SQL Injection in authentication endpoint -> Critical (48 horas)
    {
        "id": 1,
        "input": {
            "rule": "rules/sql-injection",
            "cwe": "CWE-89",
            "severity": "high",
            "confidence": "high",
            "file": "app/auth/login_controller.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "SQL injection in authentication controller with high confidence",
    },
    # 2. Hardcoded API secret verified VALID -> Critical (48 horas)
    {
        "id": 2,
        "input": {
            "rule": "trufflehog/stripe-api-key",
            "cwe": "CWE-798",
            "severity": "critical",
            "verification": "VALID",
            "file": "services/billing/credentials.py",
            "tools": ["trufflehog"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Hardcoded Stripe key verified VALID in billing service",
    },
    # 3. Secret verified INVALID in unit tests -> Low (180 días)
    {
        "id": 3,
        "input": {
            "rule": "gitleaks/generic-api-key",
            "cwe": "CWE-798",
            "severity": "low",
            "verification": "INVALID",
            "confidence": "low",
            "file": "tests/fixtures/dummy_token.json",
            "tools": ["gitleaks"],
        },
        "expected_severity": "low",
        "expected_deadline": "180 días",
        "description": "Invalid test dummy token in test fixtures",
    },
    # 4. OSV Critical vulnerable dependency CVSS 9.8 -> Critical (48 horas)
    {
        "id": 4,
        "input": {
            "rule": "osv-scanner/log4j-core/GHSA-jfh8-c2jp-5v3q",
            "cwe": "CWE-1104",
            "severity": "critical",
            "file": "pom.xml",
            "tools": ["osv-scanner"],
            "cvss": 9.8,
            "package": {"name": "log4j-core", "version": "2.14.1", "fixed_version": "2.17.1"},
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Log4Shell CVSS 9.8 remote code execution dependency",
    },
    # 5. OSV High vulnerable dependency CVSS 8.5 -> High (30 días)
    {
        "id": 5,
        "input": {
            "rule": "osv-scanner/axios/GHSA-cph5-m8f7-6c5x",
            "cwe": "CWE-1104",
            "severity": "high",
            "file": "package.json",
            "tools": ["osv-scanner"],
            "cvss": 8.5,
            "package": {"name": "axios", "version": "0.21.1", "fixed_version": "0.21.2"},
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "High CVSS 8.5 SSRF vulnerability in axios",
    },
    # 6. Low impact dependency CVSS 3.2 -> Medium (90 días)
    {
        "id": 6,
        "input": {
            "rule": "osv-scanner/urllib3/GHSA-1234",
            "cwe": "CWE-1104",
            "severity": "low",
            "file": "requirements.txt",
            "tools": ["osv-scanner"],
            "cvss": 3.2,
            "package": {"name": "urllib3", "version": "1.26.4", "fixed_version": "1.26.5"},
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Low severity CVSS 3.2 DoS dependency",
    },
    # 7. Remote Command Injection (CWE-78) in HTTP API handler -> Critical (48 horas)
    {
        "id": 7,
        "input": {
            "rule": "rules/command-injection-os-system",
            "cwe": "CWE-78",
            "severity": "high",
            "file": "api/controllers/system_admin.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "OS command execution in system administration API",
    },
    # 8. Path Traversal (CWE-22) in download endpoint -> Critical (48 horas)
    {
        "id": 8,
        "input": {
            "rule": "rules/path-traversal-open",
            "cwe": "CWE-22",
            "severity": "high",
            "file": "api/routes/download.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Arbitrary file read path traversal in public route",
    },
    # 9. Path Traversal (CWE-22) in background utility script -> High (30 días)
    {
        "id": 9,
        "input": {
            "rule": "rules/path-traversal-archive",
            "cwe": "CWE-22",
            "severity": "medium",
            "file": "utils/archive_extractor.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "Zip traversal in internal unzipping utility",
    },
    # 10. Reflected XSS (CWE-79) in web controller -> Critical (48 horas)
    {
        "id": 10,
        "input": {
            "rule": "rules/xss-render-template",
            "cwe": "CWE-79",
            "severity": "medium",
            "file": "app/views/user_profile.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "XSS in web controller view (Control 4 base 70 + 8 + 12 = 90)",
    },
    # 11. Reflected XSS (CWE-79) in test mockup -> High (30 días)
    {
        "id": 11,
        "input": {
            "rule": "rules/xss-test-helper",
            "cwe": "CWE-79",
            "severity": "medium",
            "file": "tests/mocks/mock_renderer.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "XSS template helper in mock test file (-25 exposure -> 53)",
    },
    # 12. Hadolint root user container execution -> Medium (90 días)
    {
        "id": 12,
        "input": {
            "rule": "hadolint/DL3002",
            "cwe": "CWE-250",
            "severity": "medium",
            "file": "Dockerfile",
            "tools": ["hadolint"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Dockerfile running container as root (Control 5 base 30 + 5 = 35)",
    },
    # 13. Insecure Cryptographic Algorithm (CWE-327) in auth session -> High (30 días)
    {
        "id": 13,
        "input": {
            "rule": "rules/weak-crypto-des",
            "cwe": "CWE-327",
            "severity": "high",
            "file": "services/auth/session_encryptor.py",
            "tools": ["semgrep", "bandit"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "Weak encryption algorithm in authentication session crypto",
    },
    # 14. Broken Hash MD5 (CWE-328) in cache key calculator -> Medium (90 días)
    {
        "id": 14,
        "input": {
            "rule": "bandit/B303",
            "cwe": "CWE-328",
            "severity": "low",
            "file": "cache/key_hasher.py",
            "tools": ["bandit"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "MD5 used for non-cryptographic cache hashing (50 - 10 = 40)",
    },
    # 15. Server-Side Request Forgery SSRF (CWE-918) in webhook dispatcher -> High (30 días)
    {
        "id": 15,
        "input": {
            "rule": "rules/ssrf-requests-post",
            "cwe": "CWE-918",
            "severity": "high",
            "file": "api/webhooks/forwarder.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "SSRF in webhook forwarding route (Control 9 base 50 + 8 + 12 = 70)",
    },
    # 16. Insecure Deserialization (CWE-502) in API controller -> Critical (48 horas)
    {
        "id": 16,
        "input": {
            "rule": "rules/python-pickle-load",
            "cwe": "CWE-502",
            "severity": "high",
            "file": "api/controllers/rpc_endpoint.py",
            "tools": ["semgrep", "bandit"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Pickle deserialization in public RPC endpoint (50 + 8 + 8 + 12 = 78)",
    },
    # 17. Missing Dependabot configuration -> Medium (90 días)
    {
        "id": 17,
        "input": {
            "rule": "dependabot/missing-config",
            "cwe": "CWE-1104",
            "severity": "low",
            "file": ".github/dependabot.yml",
            "tools": ["dependabot"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Missing automated dependency updates file (Control 6: 50 - 10 + 5 = 45)",
    },
    # 18. GitHub Actions workflow injection (zizmor) -> Critical (48 horas)
    {
        "id": 18,
        "input": {
            "rule": "zizmor/template-injection",
            "cwe": "CWE-78",
            "severity": "high",
            "file": ".github/workflows/ci.yml",
            "tools": ["zizmor"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Untrusted input in GitHub Actions run step (70 + 8 + 15 + 5 = 98)",
    },
    # 19. Unused dependency detected by deptry -> Medium (90 días)
    {
        "id": 19,
        "input": {
            "rule": "deptry/DEP002",
            "cwe": "CWE-1104",
            "severity": "low",
            "confidence": "low",
            "file": "requirements.txt",
            "tools": ["deptry"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Unused declared dependency in requirements.txt (50 - 10 - 10 = 30)",
    },
    # 20. Log Injection CWE-117 in general module -> Medium (90 días)
    {
        "id": 20,
        "input": {
            "rule": "rules/log-injection",
            "cwe": "CWE-117",
            "severity": "medium",
            "file": "utils/logger.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Unsanitized user input logged into file (Control 7 base 30)",
    },
    # 21. Sensitive data in logs CWE-532 in auth audit -> High (30 días)
    {
        "id": 21,
        "input": {
            "rule": "rules/password-logging",
            "cwe": "CWE-532",
            "severity": "high",
            "file": "auth/audit_log.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "Password or bearer token written to logs in auth module (30 + 8 + 15 = 53)",
    },
    # 22. Cross-Site Request Forgery CSRF (CWE-352) in payment handler -> High (30 días)
    {
        "id": 22,
        "input": {
            "rule": "rules/csrf-missing-token",
            "cwe": "CWE-352",
            "severity": "medium",
            "file": "api/controllers/billing.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "State changing API endpoint lacking anti-CSRF check (50 + 12 = 62)",
    },
    # 23. Hardcoded secret unverified in backend service -> Critical (48 horas)
    {
        "id": 23,
        "input": {
            "rule": "gitleaks/jwt-secret",
            "cwe": "CWE-798",
            "severity": "high",
            "file": "services/crypto.py",
            "tools": ["gitleaks"],
        },
        "expected_severity": "critical",
        "expected_deadline": "48 horas",
        "description": "Hardcoded JWT secret key in crypto service (70 + 8 + 15 = 93)",
    },
    # 24. Hardcoded secret unverified in sample directory -> Medium (90 días)
    {
        "id": 24,
        "input": {
            "rule": "gitleaks/api-key",
            "cwe": "CWE-798",
            "severity": "low",
            "confidence": "low",
            "file": "samples/demo_credentials.env",
            "tools": ["gitleaks"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "Sample API key in samples folder (70 - 10 + 15 - 25 - 10 = 40)",
    },
    # 25. Outdated dependency CVSS 7.2 in package-lock.json -> High (30 días)
    {
        "id": 25,
        "input": {
            "rule": "npm-audit/json-schema",
            "cwe": "CWE-1104",
            "severity": "high",
            "file": "package-lock.json",
            "tools": ["npm-audit", "osv-scanner"],
            "cvss": 7.2,
            "package": {"name": "json-schema", "version": "0.2.3", "fixed_version": "0.4.0"},
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "High CVSS 7.2 dependency vulnerability (50 + 8 + 15 = 73)",
    },
    # 26. Outdated dependency CVSS 5.0 in requirements.txt -> High (30 días)
    {
        "id": 26,
        "input": {
            "rule": "pip-audit/werkzeug",
            "cwe": "CWE-1104",
            "severity": "medium",
            "file": "requirements.txt",
            "tools": ["pip-audit"],
            "cvss": 5.0,
            "package": {"name": "werkzeug", "version": "1.0.1", "fixed_version": "2.0.0"},
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "Moderate CVSS 5.0 ReDoS in Werkzeug (50 + 0 + 5 = 55)",
    },
    # 27. Low impact dependency CVSS 2.0 with low confidence -> Low (180 días)
    {
        "id": 27,
        "input": {
            "rule": "osv-scanner/docutils",
            "cwe": "CWE-1104",
            "severity": "low",
            "confidence": "low",
            "file": "requirements.txt",
            "tools": ["osv-scanner"],
            "cvss": 2.0,
            "package": {"name": "docutils", "version": "0.14", "fixed_version": "0.16"},
        },
        "expected_severity": "low",
        "expected_deadline": "180 días",
        "description": "Low severity CVSS 2.0 docutils finding (50 - 10 - 10 - 10 = 20)",
    },
    # 28. Broken Object Level Authorization IDOR (CWE-639) in user route -> High (30 días)
    {
        "id": 28,
        "input": {
            "rule": "rules/missing-owner-check",
            "cwe": "CWE-639",
            "severity": "high",
            "file": "api/routes/user_documents.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "high",
        "expected_deadline": "30 días",
        "description": "IDOR allowing unauthorized document access (50 + 8 + 12 = 70)",
    },
    # 29. IDOR in mock test file -> Medium (90 días)
    {
        "id": 29,
        "input": {
            "rule": "rules/missing-owner-check",
            "cwe": "CWE-639",
            "severity": "high",
            "file": "tests/test_idor_scenario.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "medium",
        "expected_deadline": "90 días",
        "description": "IDOR pattern in internal test suite (-25 exposure -> 33)",
    },
    # 30. Debug stack trace exposure (CWE-209) -> Low (180 días)
    {
        "id": 30,
        "input": {
            "rule": "rules/flask-debug-true",
            "cwe": "CWE-209",
            "severity": "low",
            "file": "config/settings.py",
            "tools": ["semgrep"],
        },
        "expected_severity": "low",
        "expected_deadline": "180 días",
        "description": "Debug mode enabled in settings with low tool severity (Control 5 base 30 - 10 = 20)",
    },
]


def test_30_hand_labeled_findings_severity_calculation(capsys):
    """Test calculate_finding_severity against 30 hand-labeled findings.

    Reports the exact match count and percentage.
    """
    matches = 0
    total = len(HAND_LABELED_30_FINDINGS)
    results = []

    for item in HAND_LABELED_30_FINDINGS:
        fid = item["id"]
        inp = item["input"]
        expected_sev = item["expected_severity"]
        expected_deadline = item["expected_deadline"]

        calc_sev, calc_reason, calc_deadline = severity_engine.calculate_finding_severity(inp)

        matched = (calc_sev == expected_sev and calc_deadline == expected_deadline)
        if matched:
            matches += 1

        results.append({
            "id": fid,
            "desc": item["description"],
            "expected_sev": expected_sev,
            "calc_sev": calc_sev,
            "expected_deadline": expected_deadline,
            "calc_deadline": calc_deadline,
            "reason": calc_reason,
            "matched": matched,
        })

    match_rate = (matches / total) * 100.0
    print(f"\n==================================================")
    print(f"30 Hand-Labeled Findings Test: {matches}/{total} matched ({match_rate:.1f}%)")
    print(f"==================================================")
    for r in results:
        status_sym = "✓" if r["matched"] else "✗"
        print(f"[{status_sym}] #{r['id']:02d}: {r['desc']} -> calc: {r['calc_sev']} ({r['calc_deadline']}) | expected: {r['expected_sev']} ({r['expected_deadline']})")

    assert matches == total, f"Only {matches}/{total} findings matched expected hand labels!"


# ==============================================================================
# F4: OWASP 2021 Fallback and Mapping
# ==============================================================================

def test_cwe_owasp_2021_mapping_fallback():
    """Verify fallback to data/cwe_owasp_2021.json when rule provides no or generic category."""
    # CWE-89 SQLi -> A03:2021 - Injection
    assert severity_engine.resolve_owasp_category("CWE-89", None) == "A03:2021 - Injection"
    assert severity_engine.resolve_owasp_category("CWE-89", "") == "A03:2021 - Injection"
    assert severity_engine.resolve_owasp_category("CWE-89", "OWASP Top 10") == "A03:2021 - Injection"

    # CWE-798 Hardcoded Credentials -> A02:2021 - Cryptographic Failures
    assert severity_engine.resolve_owasp_category("CWE-798", None) == "A02:2021 - Cryptographic Failures"

    # CWE-287 Improper Authentication -> A07:2021 - Identification and Authentication Failures
    assert severity_engine.resolve_owasp_category("CWE-287", None) == "A07:2021 - Identification and Authentication Failures"

    # CWE-22 Path Traversal -> A01:2021 - Broken Access Control
    assert severity_engine.resolve_owasp_category("CWE-22", None) == "A01:2021 - Broken Access Control"

    # CWE-327 Weak Crypto -> A02:2021 - Cryptographic Failures
    assert severity_engine.resolve_owasp_category("CWE-327", "security") == "A02:2021 - Cryptographic Failures"

    # Preserves explicit specific 2021 category if provided
    assert severity_engine.resolve_owasp_category("CWE-89", "A03:2021 - Injection") == "A03:2021 - Injection"


# ==============================================================================
# F4: AI Severity Adjustment Guard (Max 1 Level & Mandatory Justification)
# ==============================================================================

def test_model_severity_adjustment_validation():
    """Verify strict constraint: AI model can only adjust 1 level and must justify."""
    # 1 level change with valid justification: accepted
    ok, sev, msg = severity_engine.validate_model_severity_change(
        "medium", "high", "Vulnerabilidad explotable directamente desde la red sin autenticación"
    )
    assert ok is True
    assert sev == "high"

    # 1 level down with valid justification: accepted
    ok, sev, msg = severity_engine.validate_model_severity_change(
        "high", "medium", "Parcialmente mitigado por control perimetral previo"
    )
    assert ok is True
    assert sev == "medium"

    # 2 levels change (e.g. low -> high): strictly rejected
    ok, sev, msg = severity_engine.validate_model_severity_change(
        "low", "high", "Considero que debería ser alta"
    )
    assert ok is False
    assert sev == "low"
    assert "solo permite 1 nivel" in msg

    # 3 levels change (e.g. critical -> low): strictly rejected
    ok, sev, msg = severity_engine.validate_model_severity_change(
        "critical", "low", "Falso positivo parcial"
    )
    assert ok is False
    assert sev == "critical"

    # Change without justification: rejected
    ok, sev, msg = severity_engine.validate_model_severity_change("medium", "high", "")
    assert ok is False
    assert sev == "medium"
    assert "sin justificación válida" in msg

    # Change with whitespace/n/a justification: rejected
    ok, sev, msg = severity_engine.validate_model_severity_change("medium", "high", "n/a")
    assert ok is False
    assert sev == "medium"

    # Invalid severity string: rejected
    ok, sev, msg = severity_engine.validate_model_severity_change("medium", "super_critical", "grave")
    assert ok is False
    assert sev == "medium"


# ==============================================================================
# F3: Deduplication by (file, line, cwe), Tool Unioning, and Path Verification
# ==============================================================================

def test_deduplication_unions_tools_and_checks_paths():
    """Verify deduplication groups by (file, line, norm_cwe), combines tools,
    keeps highest severity, and filters out non-existent files.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        real_file = tmp_path / "app.py"
        real_file.write_text("print('hello')", encoding="utf-8")

        findings = [
            {
                "file": "app.py",
                "line": 1,
                "cwe": ["CWE-89"],
                "tools": ["semgrep"],
                "severity": "medium",
                "sources": {"problem": "semgrep"},
                "references": ["ref1"],
            },
            {
                "file": "app.py",
                "line": 1,
                "cwe": ["CWE-089"],  # Same normalized CWE
                "tools": ["bandit"],
                "severity": "critical",
                "sources": {"extra": "bandit"},
                "references": ["ref2"],
            },
            {
                "file": "phantom_ghost_file.py",  # Does NOT exist
                "line": 10,
                "cwe": ["CWE-79"],
                "tools": ["semgrep"],
                "severity": "high",
            },
        ]

        deduped = analyzer._deduplicate(findings, root_dir=tmpdir)

        # Phantom file must have been eliminated
        assert len(deduped) == 1
        merged = deduped[0]
        assert merged["file"] == "app.py"
        assert set(merged["tools"]) == {"semgrep", "bandit"}
        assert merged["severity"] == "critical"
        assert "ref1" in merged["references"] and "ref2" in merged["references"]
        assert merged["sources"]["problem"] == "semgrep"
        assert merged["sources"]["extra"] == "bandit"
        assert merged["remediation_deadline"] == "48 horas"
        assert bool(merged["severity_reason"])


def test_deduplication_preserves_dependabot_missing_config():
    """Verify missing dependabot finding is kept even if .github/dependabot.yml does not exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        findings = [
            {
                "rule": "dependabot/missing-config",
                "file": ".github/dependabot.yml",
                "line": None,
                "cwe": ["CWE-1104"],
                "tools": ["dependabot"],
                "severity": "medium",
            }
        ]
        deduped = analyzer._deduplicate(findings, root_dir=tmpdir)
        assert len(deduped) == 1
        assert deduped[0]["rule"] == "dependabot/missing-config"


# ==============================================================================
# F3: OSV CVSS Extraction and Package Metadata
# ==============================================================================

def test_osv_cvss_extraction_and_fixed_version():
    """Verify CVSS score extraction and fixed version extraction from OSV data."""
    raw_osv_vuln = {
        "id": "GHSA-test-1234",
        "summary": "Sample vulnerable library",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}  # ~9.8
        ],
        "affected": [
            {
                "package": {"name": "sample-pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
            }
        ],
        "database_specific": {"cwe_ids": ["CWE-89"]},
    }

    score, vector = scanner_tools._parse_cvss_score_from_osv(raw_osv_vuln)
    assert score is not None
    assert score >= 9.0

    finding = scanner_tools._finding_from_osv(
        raw_osv_vuln, "sample-pkg", "1.0.0", "PyPI", "requirements.txt", "/tmp"
    )
    assert finding["severity"] == "critical"
    assert finding["package"]["name"] == "sample-pkg"
    assert finding["package"]["version"] == "1.0.0"
    assert finding["package"]["fixed_version"] == "1.2.3"
    assert finding["cvss"] >= 9.0


# ==============================================================================
# F3: Benchmark Tool and Scanner Pair Evaluations
# ==============================================================================

def test_benchmark_evaluate_tools_and_pairs():
    """Verify evaluate_tools_and_pairs computes metrics per tool and per pair."""
    mock_repos_results = [
        {
            "id": "repo1",
            "raw_ground_truth": [
                {"file": "app.py", "line": 10, "cwe": "CWE-89", "rule_id": "r1"},
                {"file": "config.py", "line": 5, "cwe": "CWE-798", "rule_id": "r2"},
            ],
            "raw_detected": [
                {
                    "file": "app.py",
                    "line": 10,
                    "cwe": "CWE-89",
                    "tools": ["semgrep"],
                    "matched": True,
                },
                {
                    "file": "config.py",
                    "line": 5,
                    "cwe": "CWE-798",
                    "tools": ["trufflehog"],
                    "matched": True,
                },
                {
                    "file": "ghost.py",
                    "line": 99,
                    "cwe": "CWE-79",
                    "tools": ["semgrep"],
                    "matched": False,
                },
            ],
        }
    ]

    tool_evals, scanner_pairs = benchmark_service.evaluate_tools_and_pairs(mock_repos_results)

    # Check individual tools
    tool_names = [t["tool"] for t in tool_evals]
    assert "semgrep" in tool_names
    assert "trufflehog" in tool_names

    semgrep_eval = next(t for t in tool_evals if t["tool"] == "semgrep")
    assert semgrep_eval["true_positives"] == 1
    assert semgrep_eval["false_positives"] == 1

    trufflehog_eval = next(t for t in tool_evals if t["tool"] == "trufflehog")
    assert trufflehog_eval["true_positives"] == 1
    assert trufflehog_eval["false_positives"] == 0

    # Check pair
    assert len(scanner_pairs) == 1
    pair = scanner_pairs[0]
    assert set(pair["tools"]) == {"semgrep", "trufflehog"}
    assert pair["true_positives"] == 2
    assert pair["false_positives"] == 1
    assert pair["recall"] == 1.0  # Detected both ground truth items
