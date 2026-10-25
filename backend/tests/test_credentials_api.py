"""Pruebas de endpoints de API para Credential Broker (F12)."""

import json
import pytest
from api_server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_credentials_api_lifecycle(client):
    # 1. Listar sitios inicialmente
    res = client.get("/api/credentials/sites")
    assert res.status_code == 200
    data = res.get_json()
    assert "sites" in data
    assert "total" in data

    # 2. Registrar nuevo sitio con credenciales
    new_site_payload = {
        "site_id": "api-test-portal",
        "allowed_origin": "https://portal.empresa.local",
        "username": "auditor_sec",
        "password": "PasswordSecreta999!",
        "totp_seed": "JBSWY3DPEHPK3PXP",
        "require_approval": "always",
        "max_ttl_seconds": 900,
        "owner": "auditor@neurotry.local",
        "description": "Portal corporativo para auditoría",
    }
    res_reg = client.post("/api/credentials/sites", json=new_site_payload)
    assert res_reg.status_code == 201
    reg_data = res_reg.get_json()
    assert reg_data["status"] == "ok"

    # 3. Validar que aparece en la lista sin contraseña
    res_sites = client.get("/api/credentials/sites")
    sites_json = json.dumps(res_sites.get_json())
    assert "api-test-portal" in sites_json
    assert "PasswordSecreta999!" not in sites_json

    # 4. Consultar aprobaciones
    res_appr = client.get("/api/credentials/approvals")
    assert res_appr.status_code == 200
    assert "approvals" in res_appr.get_json()

    # 5. Consultar sesiones
    res_sess = client.get("/api/credentials/sessions")
    assert res_sess.status_code == 200
    assert "sessions" in res_sess.get_json()

    # 6. Consultar auditoría
    res_audit = client.get("/api/credentials/audit")
    assert res_audit.status_code == 200
    assert "audit" in res_audit.get_json()
    assert "PasswordSecreta999!" not in json.dumps(res_audit.get_json())
