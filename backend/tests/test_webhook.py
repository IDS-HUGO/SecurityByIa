"""Pruebas pytest del webhook de GitHub.

Cubren: validación de la firma HMAC-SHA256 (comparación en tiempo constante),
extracción y saneamiento del payload de pull_request, índice persistido de
SHAs ya analizados (claim atómico y no repetición), filtrado de hallazgos a
los archivos modificados, resumen Markdown del comentario y el endpoint
POST /webhooks/github (503/403/413/200/202).

Ninguna prueba ejecuta un análisis real: el executor del API se sustituye
por un stub y los adaptadores se prueban con datos pre-armados.

Ejecución:
    python -m pytest tests/test_webhook.py -v
"""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

import api_server
import webhook_service
from webhook_service import (claim_sha, comment_markdown, extract_pr_payload,
                             filter_findings_to_files, recompute_summary,
                             verify_signature)

SECRET = "webhook-test-secret"


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def make_pr_payload(action="opened", number=7, head_sha="f" * 40, base_ref="main",
                    full_name="acme/repo"):
    return {
        "action": action,
        "pull_request": {
            "number": number,
            "head": {"sha": head_sha, "ref": "feature-x"},
            "base": {"ref": base_ref},
        },
        "repository": {"full_name": full_name, "clone_url": f"https://github.com/{full_name}.git"},
    }


@pytest.fixture()
def index_file(tmp_path, monkeypatch):
    target = tmp_path / "webhook_analyses.json"
    monkeypatch.setattr(webhook_service, "WEBHOOK_INDEX_FILE", target)
    return target


# ---------------------------------------------------------------------------
# Firma HMAC-SHA256
# ---------------------------------------------------------------------------

class TestVerifySignature:
    def test_valid_signature(self):
        body = json.dumps(make_pr_payload()).encode("utf-8")
        assert verify_signature(SECRET, sign(body), body) is True

    def test_tampered_body_rejected(self):
        body = json.dumps(make_pr_payload()).encode("utf-8")
        assert verify_signature(SECRET, sign(body), body + b" ") is False

    def test_wrong_secret_rejected(self):
        body = b"{}"
        assert verify_signature(SECRET, sign(body, "otro-secreto"), body) is False

    def test_missing_or_malformed_header_rejected(self):
        body = b"{}"
        assert verify_signature(SECRET, None, body) is False
        assert verify_signature(SECRET, "sha1=abcdef", body) is False

    def test_missing_secret_rejected(self):
        body = b"{}"
        assert verify_signature("", sign(body), body) is False


# ---------------------------------------------------------------------------
# Payload del pull_request
# ---------------------------------------------------------------------------

class TestExtractPrPayload:
    def test_full_payload(self):
        pr = extract_pr_payload(make_pr_payload())
        assert pr["number"] == 7
        assert pr["head_sha"] == "f" * 40
        assert pr["head_ref"] == "feature-x"
        assert pr["base_ref"] == "main"
        assert pr["full_name"] == "acme/repo"
        assert pr["clone_url"] == "https://github.com/acme/repo.git"

    def test_incomplete_payload_rejected(self):
        assert extract_pr_payload({"pull_request": {"number": 1}}) is None
        assert extract_pr_payload([]) is None
        assert extract_pr_payload(None) is None

    def test_unsafe_base_ref_is_neutralized(self):
        pr = extract_pr_payload(make_pr_payload(base_ref="--upload-pack=evil"))
        assert pr["base_ref"] == ""

    def test_clone_url_fallback_from_full_name(self):
        payload = make_pr_payload()
        payload["repository"]["clone_url"] = ""
        pr = extract_pr_payload(payload)
        assert pr["clone_url"] == "https://github.com/acme/repo.git"


# ---------------------------------------------------------------------------
# Índice de SHAs ya analizados
# ---------------------------------------------------------------------------

class TestShaIndex:
    def test_claim_once_then_skip(self, index_file):
        claimed, existing = claim_sha("acme/repo", "abc", {"analysis_id": "a1"})
        assert claimed is True and existing is None
        claimed_again, existing_again = claim_sha("acme/repo", "abc", {"analysis_id": "a2"})
        assert claimed_again is False
        assert existing_again["analysis_id"] == "a1"

    def test_index_persists_and_matches_case_insensitively(self, index_file):
        claim_sha("Acme/Repo", "abc", {"analysis_id": "a1"})
        existing = webhook_service.sha_already_analyzed("acme/REPO", "abc")
        assert existing["analysis_id"] == "a1"
        assert index_file.exists()


# ---------------------------------------------------------------------------
# Filtrado por archivos modificados
# ---------------------------------------------------------------------------

class TestFilterFindings:
    def test_filters_and_renumbers(self):
        result = {
            "findings": [
                {"id": 1, "file": "src/app.py", "severity": "high"},
                {"id": 2, "file": "README.md", "severity": "low"},
                {"id": 3, "file": "SRC/db.py", "severity": "critical"},
            ],
            "summary": {"total": 3, "critical": 1},
        }
        filter_findings_to_files(result, ["src/app.py", "src/db.py"])
        assert [finding["id"] for finding in result["findings"]] == [1, 2]
        assert result["findings"][0]["file"] == "src/app.py"
        assert result["findings"][1]["file"] == "SRC/db.py"
        assert result["summary"]["total"] == 2
        assert result["summary"]["critical"] == 1

    def test_recompute_summary(self):
        summary = recompute_summary([
            {"severity": "critical"}, {"severity": "low"}, {"severity": "low"},
        ])
        assert summary == {"total": 3, "critical": 1, "high": 0, "medium": 0, "low": 2}


class TestCommentMarkdown:
    def setup_method(self):
        self.pr = {"number": 7, "head_sha": "a" * 40}
        self.findings = [
            {"severity": "critical", "rule": "py-command-injection", "title": "Command injection",
             "file": "app.py", "line": 8, "tools": ["semgrep", "bandit"]},
            {"severity": "low", "rule": "depcheck/left-pad", "title": "Dependencia sin uso",
             "file": "package.json", "line": None, "tools": ["depcheck"]},
        ]

    def test_marker_and_one_line_summary(self):
        markdown = comment_markdown(self.pr, self.findings)
        assert markdown.startswith("<!-- security-control-center-analysis -->")
        assert markdown.count("**Resumen:**") == 1
        assert "2 hallazgo(s) en archivos modificados" in markdown
        assert "1 críticos" in markdown and "1 bajos" in markdown
        assert "2 nuevo(s)" in markdown  # sin corrida previa, todo es nuevo
        assert "`aaaaaaaaaaaa`" in markdown  # SHA de 12

    def test_report_link_when_base_url_given(self):
        markdown = comment_markdown(self.pr, self.findings,
                                    report_url="https://scc.example.com/api/analysis/x1")
        assert "[Reporte completo](https://scc.example.com/api/analysis/x1)" in markdown
        assert "Reporte completo" not in comment_markdown(self.pr, self.findings)

    def test_new_findings_listed_by_severity(self):
        markdown = comment_markdown(self.pr, self.findings, new_findings=[self.findings[0]])
        assert "#### 🆕 Hallazgos nuevos (por severidad)" in markdown
        critical_position = markdown.index("- **critical** — `py-command-injection`")
        assert "Command injection" in markdown[critical_position:critical_position + 200]
        assert "`app.py:8`" in markdown
        assert "semgrep, bandit" in markdown
        # El hallazgo conocido va plegado, no en la lista de nuevos
        assert "<details><summary>📋 Hallazgos ya conocidos de corridas anteriores (1)</summary>" in markdown
        assert "depcheck/left-pad" in markdown
        assert markdown.index("Hallazgos nuevos") < markdown.index("ya conocidos")

    def test_clean_message_without_findings(self):
        markdown = comment_markdown(self.pr, [])
        assert "Sin hallazgos" in markdown
        assert "0 nuevo(s)" in markdown


class TestNewFindings:
    def test_fingerprint_is_stable_and_distinct(self):
        first = {"rule": "r1", "file": "a.py", "line": 3}
        assert webhook_service.finding_fingerprint(first) == webhook_service.finding_fingerprint(dict(first))
        other = {"rule": "r1", "file": "a.py", "line": 9}
        assert webhook_service.finding_fingerprint(first) != webhook_service.finding_fingerprint(other)

    def test_split_new_and_known(self):
        findings = [
            {"rule": "r1", "file": "a.py", "line": 1, "severity": "high"},
            {"rule": "r2", "file": "b.py", "line": 2, "severity": "low"},
        ]
        previous = {webhook_service.finding_fingerprint(findings[0])}
        new, known = webhook_service.split_new_findings(findings, previous)
        assert [f["rule"] for f in new] == ["r2"]
        assert [f["rule"] for f in known] == ["r1"]

    def test_pr_state_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(webhook_service, "PR_STATE_FILE", tmp_path / "pr_state.json")
        assert webhook_service.load_previous_fingerprints("acme/repo", 7) == set()
        webhook_service.save_current_fingerprints("acme/repo", 7, "abc", [
            {"rule": "r1", "file": "a.py", "line": 1},
        ])
        loaded = webhook_service.load_previous_fingerprints("acme/repo", 7)
        assert loaded == {webhook_service.finding_fingerprint({"rule": "r1", "file": "a.py", "line": 1})}


class TestCheckOutput:
    def test_failure_explains_blocking_findings(self):
        output = webhook_service.build_check_output([
            {"severity": "critical"}, {"severity": "high"}, {"severity": "low"},
        ])
        assert output["conclusion"] == "failure"
        assert "falló" in output["title"]
        assert "1 crítico(s)" in output["summary"] and "1 alto(s)" in output["summary"]
        assert "bloquean el merge" in output["summary"]

    def test_neutral_explains_observations(self):
        output = webhook_service.build_check_output([{"severity": "medium"}, {"severity": "low"}])
        assert output["conclusion"] == "neutral"
        assert "no falla" in output["summary"]
        assert "observaciones" in output["summary"]

    def test_success_explains_clean_result(self):
        output = webhook_service.build_check_output([])
        assert output["conclusion"] == "success"
        assert "pasó" in output["title"]
        assert "sin observaciones" in output["summary"]


class TestPublishOutputs:
    def setup_method(self):
        self.pr = {"number": 7, "head_sha": "a" * 40,
                   "full_name": "acme/repo", "clone_url": "https://github.com/acme/repo.git",
                   "base_ref": "main"}
        self.result = {"findings": [{"severity": "critical", "rule": "r1", "title": "t",
                                     "file": "app.py", "line": 8, "tools": ["semgrep"]}],
                       "analysis_id": "aid-1"}

    def test_skipped_without_token(self):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("GH_TOKEN", None)
            outcomes = webhook_service.publish_pr_outputs(self.pr, self.result)
        assert outcomes == {"comment": "skipped", "check": "skipped", "new_findings": 0}

    def test_creates_comment_and_explains_check(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
        monkeypatch.setattr(webhook_service, "PR_STATE_FILE", tmp_path / "pr_state.json")
        monkeypatch.setattr(webhook_service, "_github_api_get",
                            lambda path, token: [])
        posts = []
        monkeypatch.setattr(webhook_service, "_github_api_post",
                            lambda path, token, body: posts.append((path, body)))
        outcomes = webhook_service.publish_pr_outputs(self.pr, self.result)
        assert outcomes["comment"] == "published"
        comment_path, comment_body = posts[0]
        assert comment_path == "/repos/acme/repo/issues/7/comments"
        assert webhook_service.COMMENT_MARKER in comment_body["body"]
        check_path, check_body = posts[1]
        assert check_path == "/repos/acme/repo/check-runs"
        assert check_body["conclusion"] == "failure"
        assert "falló" in check_body["output"]["title"]
        assert "bloquean el merge" in check_body["output"]["summary"]
        # La corrida quedó registrada para la próxima comparación de nuevos
        assert webhook_service.load_previous_fingerprints("acme/repo", 7)

    def test_updates_existing_comment_instead_of_duplicating(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
        monkeypatch.setattr(webhook_service, "PR_STATE_FILE", tmp_path / "pr_state.json")
        monkeypatch.setattr(webhook_service, "_github_api_get", lambda path, token: [
            {"id": 99, "body": f"{webhook_service.COMMENT_MARKER} comentario previo"}])
        patches = []
        monkeypatch.setattr(webhook_service, "_github_api_patch",
                            lambda path, token, body: patches.append((path, body)))
        monkeypatch.setattr(webhook_service, "_github_api_post", lambda *a, **k: None)
        outcomes = webhook_service.publish_pr_outputs(self.pr, self.result)
        assert outcomes["comment"] == "updated"
        assert patches[0][0] == "/repos/acme/repo/issues/comments/99"

    def test_includes_report_link_from_base_url(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
        monkeypatch.setenv("REPORT_BASE_URL", "https://scc.example.com/")
        monkeypatch.setattr(webhook_service, "PR_STATE_FILE", tmp_path / "pr_state.json")
        monkeypatch.setattr(webhook_service, "_github_api_get", lambda path, token: [])
        captured = {}
        monkeypatch.setattr(webhook_service, "_github_api_post",
                            lambda path, token, body: captured.setdefault(path, body))
        webhook_service.publish_pr_outputs(self.pr, self.result)
        body = captured["/repos/acme/repo/issues/7/comments"]["body"]
        assert "[Reporte completo](https://scc.example.com/api/analysis/aid-1)" in body


# ---------------------------------------------------------------------------
# Endpoint POST /webhooks/github
# ---------------------------------------------------------------------------

class TestWebhookEndpoint:
    def setup_method(self):
        api_server.app.config["TESTING"] = True
        self.client = api_server.app.test_client()
        self.saved_jobs = dict(api_server.jobs)
        api_server.jobs.clear()

    def teardown_method(self):
        api_server.jobs.clear()
        api_server.jobs.update(self.saved_jobs)

    def _post(self, payload, event="pull_request", secret=SECRET, sign_body=True, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
        if sign_body:
            headers["X-Hub-Signature-256"] = sign(body)
        with patch.object(api_server, "GITHUB_WEBHOOK_SECRET", secret), \
             patch.object(api_server, "analysis_executor", MagicMock()):
            return self.client.post("/webhooks/github", data=body, headers=headers)

    def test_503_without_secret_configured(self):
        response = self._post(make_pr_payload(), secret="")
        assert response.status_code == 503
        assert "GITHUB_WEBHOOK_SECRET" in response.get_json()["error"]

    def test_403_with_missing_signature(self):
        response = self._post(make_pr_payload(), sign_body=False)
        assert response.status_code == 403

    def test_413_oversized_payload(self):
        oversized = b"x" * (api_server.WEBHOOK_MAX_BODY_BYTES + 1)
        response = self._post(None, raw=oversized)
        assert response.status_code == 413

    def test_ping_answers_pong(self):
        response = self._post({"zen": "ok"}, event="ping")
        assert response.status_code == 200
        assert response.get_json()["status"] == "pong"

    def test_other_events_ignored(self):
        response = self._post({"action": "published"}, event="issues")
        assert response.status_code == 200
        assert response.get_json()["status"] == "ignored"

    def test_non_relevant_pr_actions_ignored(self):
        response = self._post(make_pr_payload(action="closed"))
        assert response.status_code == 200
        assert response.get_json()["status"] == "ignored"

    def test_pull_request_enqueues_analysis(self, index_file):
        response = self._post(make_pr_payload())
        assert response.status_code == 202
        data = response.get_json()
        assert data["stage"] == "queued"
        assert data["pr"] == 7
        assert api_server.jobs[data["analysis_id"]]["stage"] == "queued"
        saved = json.loads(index_file.read_text(encoding="utf-8"))
        assert any(entry["head_sha"] == "f" * 40 for entry in saved.values())

    def test_same_sha_is_not_repeated(self, index_file):
        first = self._post(make_pr_payload())
        assert first.status_code == 202
        second = self._post(make_pr_payload())
        assert second.status_code == 200
        assert second.get_json()["reason"] == "sha-already-analyzed"


class TestCheckThreshold:
    """Umbral configurable del check: por defecto falla solo con críticos NUEVOS."""

    def test_default_threshold_new_critical_only(self, monkeypatch):
        monkeypatch.delenv("CHECK_FAIL_SEVERITY", raising=False)
        monkeypatch.delenv("CHECK_FAIL_ONLY_NEW", raising=False)
        known_critical = {"rule": "r-old", "file": "a.py", "line": 1, "severity": "critical"}
        new_high = {"rule": "r-new", "file": "b.py", "line": 2, "severity": "high"}
        previous = {webhook_service.finding_fingerprint(known_critical)}
        new_findings, _known = webhook_service.split_new_findings(
            [known_critical, new_high], previous)
        output = webhook_service.build_check_output(
            [known_critical, new_high], new_findings=new_findings)
        assert output["conclusion"] == "neutral"
        assert "NUEVOS" in output["summary"]

    def test_new_critical_fails_by_default(self, monkeypatch):
        monkeypatch.delenv("CHECK_FAIL_SEVERITY", raising=False)
        monkeypatch.delenv("CHECK_FAIL_ONLY_NEW", raising=False)
        new_critical = {"rule": "r-new", "file": "a.py", "line": 1, "severity": "critical"}
        output = webhook_service.build_check_output([new_critical], new_findings=[new_critical])
        assert output["conclusion"] == "failure"
        assert "critical" in output["title"]
        assert "NUEVOS" in output["summary"]
        assert "bloquean el merge" in output["summary"]

    def test_threshold_severity_configurable(self, monkeypatch):
        monkeypatch.setenv("CHECK_FAIL_SEVERITY", "high")
        new_high = {"rule": "r-new", "file": "b.py", "line": 2, "severity": "high"}
        output = webhook_service.build_check_output([new_high], new_findings=[new_high])
        assert output["conclusion"] == "failure"

    def test_only_new_false_evaluates_all_findings(self, monkeypatch):
        monkeypatch.setenv("CHECK_FAIL_ONLY_NEW", "false")
        known_critical = {"rule": "r-old", "file": "a.py", "line": 1, "severity": "critical"}
        output = webhook_service.build_check_output([known_critical], new_findings=[])
        assert output["conclusion"] == "failure"
        assert "todos los hallazgos" in output["summary"]


class TestSecaiIgnore:
    def test_missing_file_means_no_patterns(self, tmp_path):
        assert webhook_service.load_secai_ignore_patterns(str(tmp_path)) == []

    def test_loads_ignore_mapping(self, tmp_path):
        (tmp_path / ".secai-ignore.yml").write_text(
            "ignore:\n  - 'tests/**'\n  - 'docs/*'\n", encoding="utf-8")
        assert webhook_service.load_secai_ignore_patterns(str(tmp_path)) == ["tests/**", "docs/*"]

    def test_loads_top_level_list(self, tmp_path):
        (tmp_path / ".secai-ignore.yml").write_text("- 'fixtures/*'\n", encoding="utf-8")
        assert webhook_service.load_secai_ignore_patterns(str(tmp_path)) == ["fixtures/*"]

    def test_invalid_yaml_means_no_patterns(self, tmp_path):
        (tmp_path / ".secai-ignore.yml").write_text("::: no es yaml [[[\n", encoding="utf-8")
        assert webhook_service.load_secai_ignore_patterns(str(tmp_path)) == []

    def test_path_is_ignored_semantics(self):
        patterns = ["tests/**", "docs/*"]
        assert webhook_service.path_is_ignored("tests/unit/x.py", patterns) is True
        assert webhook_service.path_is_ignored("docs/a.md", patterns) is True
        assert webhook_service.path_is_ignored("src/app.py", patterns) is False

    def test_filter_ignored_findings_removes_and_renumbers(self):
        result = {
            "findings": [
                {"id": 1, "file": "tests/x.py", "severity": "critical"},
                {"id": 2, "file": "app.py", "severity": "high"},
            ],
            "summary": {"total": 2, "critical": 1},
        }
        removed = webhook_service.filter_ignored_findings(result, ["tests/**"])
        assert removed == 1
        assert [finding["file"] for finding in result["findings"]] == ["app.py"]
        assert [finding["id"] for finding in result["findings"]] == [1]
        assert result["summary"]["total"] == 1
