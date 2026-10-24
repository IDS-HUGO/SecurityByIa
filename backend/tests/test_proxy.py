"""Pruebas pytest del proxy de secretos y APIs (F8).

Cubren: acceso permitido (con inyección del secreto según la ruta y auditoría),
acceso denegado (token inválido, sin scope, ruta no permitida), destino fuera
de la lista blanca, límite de tasa, fail-closed del cliente con el proxy caído,
redacción de secretos en respuestas y errores, verificación con Gitleaks de que
la auditoría no filtra secretos (con control positivo) y rotación de tokens.

No requiere red: el upstream se sustituye por un stub de urllib.

Ejecución:
    python -m pytest tests/test_proxy.py -v
"""

import hashlib
import json
import os
import shutil
import subprocess
import urllib.error

import pytest

from proxy import client as proxy_client
from proxy import server as proxy_server


SECRET = "AIza" + "A0z9-_x" * 5  # formato de Google API key (39 chars, regla default de Gitleaks)
TOKEN_A = "tok-demo-AAAA"
TOKEN_B = "tok-demo-BBBB"


class FakeUpstreamResponse:
    def __init__(self, body, status=200):
        if isinstance(body, str):
            self._body = body.encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            self._body = bytes(body)
        else:
            self._body = json.dumps(body).encode("utf-8")
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def write_tokens(path, token, providers=("gemini",), limit=30, token_id="demo-triage"):
    path.write_text(json.dumps([{
        "id": token_id,
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "providers": list(providers),
        "rate_limit_per_minute": limit,
    }]), encoding="utf-8")
    return path


@pytest.fixture()
def proxy_env(tmp_path, monkeypatch):
    tokens_file = write_tokens(tmp_path / "tokens.json", TOKEN_A)
    audit_file = tmp_path / "audit" / "proxy_audit.jsonl"
    monkeypatch.setattr(proxy_server, "PROXY_TOKENS_FILE", str(tokens_file))
    monkeypatch.setattr(proxy_server, "AUDIT_FILE", audit_file)
    monkeypatch.setattr(proxy_server, "_rate_hits", {})  # estado entre tests no contamina
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return {"tokens_file": tokens_file, "audit_file": audit_file, "tmp": tmp_path}


def post(client, path, token=TOKEN_A, body=None):
    return client.post(path, data=json.dumps(body or {"prompt": "x"}), headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    })


def stub_upstream(monkeypatch, body=None, status=200, raise_error=None):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {key.title(): value for key, value in req.header_items()}
        if raise_error is not None:
            raise raise_error
        return FakeUpstreamResponse(body, status)

    monkeypatch.setattr(proxy_server.urllib.request, "urlopen", fake_urlopen)
    return captured


# ---------------------------------------------------------------------------
# Acceso permitido: inyección del secreto según la ruta + auditoría
# ---------------------------------------------------------------------------

def test_allowed_access_injects_secret_and_audits(proxy_env, monkeypatch):
    captured = stub_upstream(monkeypatch, body={"ok": True})
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent")

    assert response.status_code == 200
    assert captured["url"].startswith("https://generativelanguage.googleapis.com/v1beta/models/")
    assert captured["headers"].get("X-Goog-Api-Key") == SECRET, "el proxy inyecta la clave según la ruta"
    assert "Authorization" not in captured["headers"], "el token limitado nunca viaja al proveedor"

    entries = proxy_server.read_audit_entries(10)
    assert entries and entries[0]["result"] == "allowed"
    assert entries[0]["token_id"] == "demo-triage"
    assert entries[0]["service"] == "gemini"
    assert entries[0]["route"] == "gemini/models/gemini-1.5-flash:generateContent"


def test_audit_and_response_never_contain_the_secret(proxy_env, monkeypatch):
    stub_upstream(monkeypatch, body={"echo": SECRET})
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent")

    assert response.status_code == 200
    assert SECRET not in response.get_data(as_text=True), "la respuesta se redacta"
    assert "[REDACTED]" in response.get_data(as_text=True)
    audit_text = proxy_env["audit_file"].read_text(encoding="utf-8")
    assert SECRET not in audit_text, "la auditoría jamás registra el secreto"


def test_upstream_error_is_redacted_and_returns_502(proxy_env, monkeypatch):
    stub_upstream(monkeypatch, raise_error=urllib.error.URLError(f"connection refused to {SECRET}"))
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent")

    assert response.status_code == 502
    assert SECRET not in response.get_json()["error"]


# ---------------------------------------------------------------------------
# Acceso denegado y fail-closed
# ---------------------------------------------------------------------------

def test_invalid_token_denied(proxy_env):
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent", token="tok-incorrecto")
    assert response.status_code == 401
    entries = proxy_server.read_audit_entries(10)
    assert entries[0]["result"].startswith("denied:")
    assert entries[0]["token_id"] is None


def test_token_without_provider_scope_denied(tmp_path, proxy_env, monkeypatch):
    write_tokens(proxy_env["tokens_file"], TOKEN_A, providers=("openai",))
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent")
    assert response.status_code == 403


def test_destination_outside_whitelist_denied(proxy_env):
    client = proxy_server.app.test_client()
    response = post(client, "/evil/models/x:generateContent")
    assert response.status_code == 403
    assert "lista blanca" in response.get_json()["error"]


def test_provider_path_not_allowlisted_denied(proxy_env):
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/admin/secrets")
    assert response.status_code == 403


def test_rate_limit_per_token(proxy_env, monkeypatch):
    write_tokens(proxy_env["tokens_file"], TOKEN_A, limit=1)
    stub_upstream(monkeypatch, body={"ok": True})
    client = proxy_server.app.test_client()
    assert post(client, "/gemini/models/gemini-1.5-flash:generateContent").status_code == 200
    second = post(client, "/gemini/models/gemini-1.5-flash:generateContent")
    assert second.status_code == 429


def test_missing_provider_secret_fails_closed(proxy_env, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    stub_upstream(monkeypatch, body={"ok": True})
    client = proxy_server.app.test_client()
    response = post(client, "/gemini/models/gemini-1.5-flash:generateContent")
    assert response.status_code == 503
    assert "clave" in response.get_json()["error"]


def test_healthz_lists_whitelist():
    client = proxy_server.app.test_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert set(response.get_json()["providers"]) == {"gemini", "openai", "claude"}


# ---------------------------------------------------------------------------
# Rotación de tokens
# ---------------------------------------------------------------------------

def test_token_rotation(proxy_env, monkeypatch):
    stub_upstream(monkeypatch, body={"ok": True})
    client = proxy_server.app.test_client()
    assert post(client, "/gemini/models/gemini-1.5-flash:generateContent").status_code in (200, 502)

    # Rotación: se reemplaza el hash del token; el viejo muere de inmediato.
    write_tokens(proxy_env["tokens_file"], TOKEN_B, token_id="demo-triage")
    assert post(client, "/gemini/models/gemini-1.5-flash:generateContent", token=TOKEN_A).status_code == 401
    assert post(client, "/gemini/models/gemini-1.5-flash:generateContent", token=TOKEN_B).status_code == 200


# ---------------------------------------------------------------------------
# Cliente de los agentes: fail-closed con el proxy caído
# ---------------------------------------------------------------------------

def test_client_fails_closed_when_proxy_is_down(monkeypatch):
    monkeypatch.setenv("SECURITY_PROXY_URL", "http://127.0.0.1:9")  # puerto cerrado
    monkeypatch.setenv("SECURITY_PROXY_TOKEN", "tok-demo-AAAA")
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)  # existe, pero NUNCA debe usarse directo
    with pytest.raises(proxy_client.ProxyUnavailable):
        proxy_client.model_request("gemini", "models/gemini-1.5-flash:generateContent", {"x": 1}, timeout=2)


def test_client_fails_closed_without_token(monkeypatch):
    monkeypatch.setenv("SECURITY_PROXY_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("SECURITY_PROXY_TOKEN", raising=False)
    with pytest.raises(proxy_client.ProxyUnavailable):
        proxy_client.model_request("gemini", "models/gemini-1.5-flash:generateContent", {})


def test_client_unconfigured_raises(monkeypatch):
    monkeypatch.delenv("SECURITY_PROXY_URL", raising=False)
    assert proxy_client.proxy_configured() is False
    with pytest.raises(proxy_client.ProxyUnavailable):
        proxy_client.model_request("gemini", "models/gemini-1.5-flash:generateContent", {})


# ---------------------------------------------------------------------------
# Verificación con Gitleaks: la auditoría no filtra el secreto
# ---------------------------------------------------------------------------

def _gitleaks_binary():
    return shutil.which("gitleaks") or os.environ.get("GITLEAKS_PATH")


def test_gitleaks_audit_has_no_secret_leak(proxy_env, monkeypatch):
    gitleaks = _gitleaks_binary()
    if not gitleaks:
        pytest.skip("Gitleaks no está instalado en este entorno")

    # Escenario que habría filtrado: el upstream repite el secreto en la respuesta.
    stub_upstream(monkeypatch, body={"echo": SECRET})
    client = proxy_server.app.test_client()
    assert post(client, "/gemini/models/gemini-1.5-flash:generateContent").status_code == 200

    # Control positivo: Gitleaks detecta el secreto en claro donde SÍ existe.
    control_dir = proxy_env["tmp"] / "control"
    control_dir.mkdir()
    (control_dir / "raw.txt").write_text(SECRET, encoding="utf-8")
    control_report = proxy_env["tmp"] / "control-report.json"
    control_run = subprocess.run(
        [gitleaks, "detect", "--source", str(control_dir), "--no-git",
         "--report-format", "json", "--report-path", str(control_report), "--no-banner"],
        capture_output=True, timeout=120)
    assert control_run.returncode == 1, "Gitleaks debe detectar el secreto en claro (control positivo)"

    # Objetivo: la auditoría redactada queda limpia para Gitleaks.
    audit_dir = proxy_env["tmp"] / "audit-scan"
    audit_dir.mkdir()
    (audit_dir / "proxy_audit.jsonl").write_text(
        proxy_env["audit_file"].read_text(encoding="utf-8"), encoding="utf-8")
    audit_report = proxy_env["tmp"] / "audit-report.json"
    audit_run = subprocess.run(
        [gitleaks, "detect", "--source", str(audit_dir), "--no-git",
         "--report-format", "json", "--report-path", str(audit_report), "--no-banner"],
        capture_output=True, timeout=120)
    assert audit_run.returncode == 0, (
        "Gitleaks no debe encontrar secretos en la auditoría del proxy")
