"""Tests for CORS enforcement (Control 1 of Security Controls Inventory):
- Explicit list of allowed origins from environment variable CORS_ALLOWED_ORIGINS.
- NO wildcard '*' allowed.
- NO Access-Control-Allow-Credentials allowed.
- Unauthorized / alien origins MUST NOT receive Access-Control-Allow-Origin.
- Preflight OPTIONS requests handled cleanly.
"""

import os
from unittest.mock import patch
import pytest

from api_server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_allowed_origin_receives_exact_cors_header(client):
    """When a configured allowed origin sends a request, it receives its exact origin in Access-Control-Allow-Origin."""
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173"}):
        res = client.get("/api/analyses", headers={"Origin": "http://localhost:5173"})
        assert res.status_code == 200
        # Exact match, never wildcard
        assert res.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        assert res.headers.get("Access-Control-Allow-Origin") != "*"
        # No credentials allowed
        assert res.headers.get("Access-Control-Allow-Credentials") is None or res.headers.get("Access-Control-Allow-Credentials") != "true"


def test_alien_origin_does_not_receive_cors_header(client):
    """An unauthorized origin (e.g. attacker domain) must NEVER receive Access-Control-Allow-Origin."""
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173"}):
        res = client.get("/api/analyses", headers={"Origin": "https://evil-attacker.example.com"})
        assert res.status_code == 200
        # MUST NOT have Access-Control-Allow-Origin header
        assert "Access-Control-Allow-Origin" not in res.headers


def test_wildcard_is_never_allowed(client):
    """Wildcard '*' must never be accepted or emitted as an allowed origin."""
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
        res = client.get("/api/analyses", headers={"Origin": "*"})
        assert "Access-Control-Allow-Origin" not in res.headers or res.headers.get("Access-Control-Allow-Origin") != "*"


def test_cors_options_preflight_allowed_origin(client):
    """Preflight OPTIONS request from an allowed origin returns 200/204 with CORS headers."""
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
        res = client.options("/api/analyze", headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        })
        assert res.status_code in (200, 204)
        assert res.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        assert "POST" in res.headers.get("Access-Control-Allow-Methods", "")


def test_cors_options_preflight_alien_origin(client):
    """Preflight OPTIONS request from an unauthorized origin must not receive Access-Control-Allow-Origin."""
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
        res = client.options("/api/analyze", headers={
            "Origin": "https://unauthorized-domain.com",
            "Access-Control-Request-Method": "POST",
        })
        assert "Access-Control-Allow-Origin" not in res.headers


def test_dynamic_cors_origin_configuration(client):
    """Adding a custom origin via CORS_ALLOWED_ORIGINS takes immediate effect."""
    custom_origin = "https://internal-dashboard.company.local"
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": f"http://localhost:5173,{custom_origin}"}):
        res = client.get("/api/bench", headers={"Origin": custom_origin})
        assert res.status_code == 200
        assert res.headers.get("Access-Control-Allow-Origin") == custom_origin
