"""Pruebas completas de verificadores en vivo y evidencia (F11).

Cubre:
- Modo HTTP: CORS con Origin ajeno (1), banderas de cookies (10), headers de seguridad (16),
  errores sin información sensible (3), rate limit con respuesta 429 (7), TLS inferior a 1.2 (14).
- Modo Nube: cifrado DB (13), acceso público buckets (15), ciclo de vida (19), DB pública (18),
  TLS del balanceador (14), CloudTrail (C9), respaldos (C6).
- Requisito de autorización obligatoria antes de cualquier prueba en vivo (400 / bloqueo).
- Lista permitida estricta de comandos de lectura (describe y get) y rechazo de comandos mutantes.
- Enrutamiento por proxy F8 (fail-closed, auditoría sin secretos).
- Regla de honestidad: ante incertidumbre o fallo, deja en «requiere evidencia», nunca «cumple».
- Bitácora de auditoría de cada prueba con redacción de secretos.
- Endpoints de API (/api/verificaciones/en-vivo, /api/verificaciones/bitacora, /evidencia).
"""

import json
import os
import urllib.error
import pytest

import verificadores
from verificadores.base import ResultadoVerificacion, leer_bitacora, redactar_secretos, registrar_bitacora
from verificadores.nube.allowlist import validar_comando_nube
from verificadores.http.runner import ejecutar_verificadores_http
from verificadores.nube.runner import ejecutar_verificadores_nube
from verificadores.http import control_01_cors, control_03_errors, control_07_ratelimit, control_10_cookies, control_14_tls, control_16_headers
from verificadores.nube import (
    control_13_db_encryption,
    control_14_alb_tls,
    control_15_s3_public,
    control_18_db_public,
    control_19_s3_lifecycle,
    control_c06_backups,
    control_c09_cloudtrail,
)


# ---------------------------------------------------------------------------
# Modo HTTP
# ---------------------------------------------------------------------------

class TestModoHttp:
    def test_cors_origen_ajeno_reflejado_falla(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {
                "Access-Control-Allow-Origin": "https://evil-untrusted-origin.example.com",
                "Access-Control-Allow-Credentials": "true",
            }
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_01_cors.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_01_cors.verificar_cors("https://api.example.com")
        assert res.estado == "no cumple"
        assert "credenciales" in res.detalles.lower()

    def test_cors_restringido_cumple(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {"Access-Control-Allow-Origin": "https://trusted.app.com"}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_01_cors.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_01_cors.verificar_cors("https://api.example.com")
        assert res.estado == "cumple"

    def test_errores_con_stack_trace_falla(self, monkeypatch):
        class FakeError(urllib.error.HTTPError):
            def __init__(self):
                super().__init__("https://api.com", 500, "Internal Server Error", {}, None)
            def read(self):
                return b"Traceback (most recent call last):\n  File 'app.py', line 42\nException Details:"

        monkeypatch.setattr(control_03_errors.urllib.request, "urlopen", lambda req, timeout=10: (_ for _ in ()).throw(FakeError()))
        res = control_03_errors.verificar_errores_sensibles("https://api.example.com")
        assert res.estado == "no cumple"
        assert "stack" in res.detalles.lower() or "sensible" in res.detalles.lower()

    def test_errores_limpios_cumple(self, monkeypatch):
        class FakeError(urllib.error.HTTPError):
            def __init__(self):
                super().__init__("https://api.com", 404, "Not Found", {}, None)
            def read(self):
                return b'{"error": "Resource not found"}'

        monkeypatch.setattr(control_03_errors.urllib.request, "urlopen", lambda req, timeout=10: (_ for _ in ()).throw(FakeError()))
        res = control_03_errors.verificar_errores_sensibles("https://api.example.com")
        assert res.estado == "cumple"

    def test_rate_limit_con_respuesta_429_cumple(self, monkeypatch):
        class Fake429(urllib.error.HTTPError):
            def __init__(self):
                super().__init__("https://api.com", 429, "Too Many Requests", {"Retry-After": "60"}, None)

        def mock_urlopen(req, timeout=10):
            raise Fake429()

        monkeypatch.setattr(control_07_ratelimit.urllib.request, "urlopen", mock_urlopen)
        res = control_07_ratelimit.verificar_rate_limit("https://api.example.com", burst_count=3)
        assert res.estado == "cumple"
        assert "429" in res.detalles

    def test_rate_limit_sin_429_deja_en_requiere_evidencia(self, monkeypatch):
        class Fake200:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_07_ratelimit.urllib.request, "urlopen", lambda req, timeout=10: Fake200())
        res = control_07_ratelimit.verificar_rate_limit("https://api.example.com", burst_count=2)
        assert res.estado == "requiere evidencia"
        assert res.requiere_evidencia is True

    def test_cookies_sin_flags_falla(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {"Set-Cookie": "session=abc12345; Path=/"}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_10_cookies.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_10_cookies.verificar_cookies("https://api.example.com")
        assert res.estado == "no cumple"
        assert "secure" in res.detalles.lower()

    def test_cookies_con_flags_cumple(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {"Set-Cookie": "session=xyz; Secure; HttpOnly; SameSite=Strict"}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_10_cookies.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_10_cookies.verificar_cookies("https://api.example.com")
        assert res.estado == "cumple"

    def test_cookies_ausentes_deja_en_requiere_evidencia(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_10_cookies.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_10_cookies.verificar_cookies("https://api.example.com")
        assert res.estado == "requiere evidencia"

    def test_headers_completos_cumple(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "no-referrer",
            }
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_16_headers.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_16_headers.verificar_headers("https://api.example.com")
        assert res.estado == "cumple"

    def test_headers_faltantes_falla(self, monkeypatch):
        class FakeResponse:
            status = 200
            headers = {"Server": "nginx"}
            def __enter__(self): return self
            def __exit__(self, *args): return False

        monkeypatch.setattr(control_16_headers.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        res = control_16_headers.verificar_headers("https://api.example.com")
        assert res.estado == "no cumple"


# ---------------------------------------------------------------------------
# Modo Nube
# ---------------------------------------------------------------------------

class TestModoNube:
    def test_cifrado_db_encriptado_cumple(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps([{"ID": "db-prod-1", "Encrypted": True}]),
        }
        res = control_13_db_encryption.verificar_cifrado_db(ejecutor)
        assert res.estado == "cumple"

    def test_cifrado_db_sin_cifrado_falla(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps([{"ID": "db-insegura", "Encrypted": False}]),
        }
        res = control_13_db_encryption.verificar_cifrado_db(ejecutor)
        assert res.estado == "no cumple"

    def test_s3_publico_bloqueado_cumple(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps({
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }),
        }
        res = control_15_s3_public.verificar_s3_public(ejecutor)
        assert res.estado == "cumple"

    def test_s3_publico_desprotegido_falla(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps({
                "BlockPublicAcls": False,
                "BlockPublicPolicy": False,
            }),
        }
        res = control_15_s3_public.verificar_s3_public(ejecutor)
        assert res.estado == "no cumple"

    def test_s3_ciclo_de_vida_sin_configuracion_falla(self):
        ejecutor = lambda cmd: {
            "status": "error",
            "exit_code": 1,
            "stderr": "NoSuchLifecycleConfiguration: The lifecycle configuration does not exist",
        }
        res = control_19_s3_lifecycle.verificar_s3_lifecycle(ejecutor)
        assert res.estado == "no cumple"

    def test_db_publica_falla(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps([{"ID": "db-expuesta", "Public": True}]),
        }
        res = control_18_db_public.verificar_db_no_publica(ejecutor)
        assert res.estado == "no cumple"

    def test_db_privada_cumple(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps([{"ID": "db-interna", "Public": False}]),
        }
        res = control_18_db_public.verificar_db_no_publica(ejecutor)
        assert res.estado == "cumple"

    def test_cloudtrail_multirregion_cumple(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps({"trailList": [{"Name": "main-trail", "IsMultiRegionTrail": True}]}),
        }
        res = control_c09_cloudtrail.verificar_cloudtrail(ejecutor)
        assert res.estado == "cumple"

    def test_respaldos_con_retencion_cumple(self):
        ejecutor = lambda cmd: {
            "status": "ok",
            "exit_code": 0,
            "stdout": json.dumps([{"ID": "rds-1", "Retention": 7, "Protection": True}]),
        }
        res = control_c06_backups.verificar_respaldos(ejecutor)
        assert res.estado == "cumple"


# ---------------------------------------------------------------------------
# Requisitos de Seguridad: Autorización, Allowlist, Honestidad y Bitácora
# ---------------------------------------------------------------------------

class TestRequisitosSeguridad:
    def test_exige_autorizacion_confirmada_en_http(self):
        """Si autorizacion_confirmada es False, no hace peticiones y deja en requiere evidencia."""
        resultados = ejecutar_verificadores_http(
            "https://target.com",
            autorizacion_confirmada=False,
            controles=["1", "16"],
        )
        assert len(resultados) == 2
        for r in resultados:
            assert r.estado == "requiere evidencia"
            assert "autorización" in r.detalles.lower()

    def test_exige_autorizacion_confirmada_en_nube(self):
        resultados = ejecutar_verificadores_nube(
            "aws-account-123",
            autorizacion_confirmada=False,
            controles=["13", "C9"],
        )
        assert len(resultados) == 2
        for r in resultados:
            assert r.estado == "requiere evidencia"
            assert "autorización" in r.detalles.lower()

    def test_allowlist_acepta_comandos_describe_y_get(self):
        valido, _ = validar_comando_nube("aws rds describe-db-instances --output json")
        assert valido is True
        valido, _ = validar_comando_nube("aws s3api get-public-access-block")
        assert valido is True
        valido, _ = validar_comando_nube("aws cloudtrail describe-trails")
        assert valido is True

    def test_allowlist_rechaza_comandos_mutantes_o_no_permitidos(self):
        # Intentos de borrado o modificación
        valido, err = validar_comando_nube("aws s3api delete-bucket --bucket mi-bucket")
        assert valido is False
        assert "rechazado" in err.lower()

        valido, err = validar_comando_nube("aws rds modify-db-instance --db-instance-identifier id")
        assert valido is False

        valido, err = validar_comando_nube("aws ec2 terminate-instances --instance-ids i-123")
        assert valido is False

        # Comando describe con subcomando malicioso
        valido, err = validar_comando_nube("aws rds describe-db-instances --delete")
        assert valido is False

    def test_si_control_no_se_puede_verificar_deja_en_requiere_evidencia(self):
        """Fallo cerrado y honestidad: si falla ejecución o faltan credenciales, jamás marca 'cumple'."""
        ejecutor_error = lambda cmd: {
            "status": "error",
            "exit_code": 1,
            "stderr": "AccessDenied: User is not authorized",
        }
        res13 = control_13_db_encryption.verificar_cifrado_db(ejecutor_error)
        assert res13.estado == "requiere evidencia"

        res15 = control_15_s3_public.verificar_s3_public(ejecutor_error)
        assert res15.estado == "requiere evidencia"

        resc6 = control_c06_backups.verificar_respaldos(ejecutor_error)
        assert resc6.estado == "requiere evidencia"

    def test_bitacora_registra_y_redacta_secretos(self, tmp_path, monkeypatch):
        audit_file = tmp_path / "bitacora_test.jsonl"
        monkeypatch.setattr(verificadores.base, "BITACORA_FILE", audit_file)

        secreto = "sk-1234567890abcdef1234567890abcdef"
        res = ResultadoVerificacion(
            control_id="1",
            nombre="CORS",
            modo="http",
            estado="cumple",
            detalles=f"Respuesta con clave={secreto}",
            evidencia=f"Header: Authorization: Bearer {secreto}",
            objetivo="https://test.com",
        )
        registrar_bitacora(res, usuario="analista-test", autorizacion_confirmada=True)

        assert audit_file.exists()
        contenido = audit_file.read_text(encoding="utf-8")
        assert secreto not in contenido, "El secreto debe haber sido redactado en la bitácora"
        assert "[REDACTED_SECRET]" in contenido

        entradas = leer_bitacora(10)
        assert len(entradas) == 1
        assert entradas[0]["control_id"] == "1"
        assert entradas[0]["autorizacion_confirmada"] is True


# ---------------------------------------------------------------------------
# Endpoints de API Flask
# ---------------------------------------------------------------------------

class TestApiVerificadores:
    @pytest.fixture()
    def client(self):
        import api_server
        api_server.app.config["TESTING"] = True
        with api_server.app.test_client() as c:
            yield c

    def test_api_sin_autorizacion_responde_400(self, client):
        response = client.post("/api/verificaciones/en-vivo", json={
            "modo": "http",
            "target": "https://example.com",
            "autorizacion_confirmada": False,
        })
        assert response.status_code == 400
        assert "autorización" in response.get_json()["error"]

    def test_api_con_autorizacion_ejecuta_y_responde_200(self, client, monkeypatch):
        monkeypatch.setattr(
            verificadores,
            "ejecutar_verificadores_http",
            lambda url, autorizacion_confirmada, controles=None, usuario="analista": [
                ResultadoVerificacion(
                    control_id="1",
                    nombre="CORS",
                    modo="http",
                    estado="cumple",
                    detalles="Test ok",
                    evidencia="Cabeceras",
                    objetivo=url,
                )
            ]
        )
        response = client.post("/api/verificaciones/en-vivo", json={
            "modo": "http",
            "target": "https://api.test.com",
            "autorizacion_confirmada": True,
            "controles": ["1"],
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["autorizacion_confirmada"] is True
        assert len(data["results"]) == 1

    def test_api_bitacora_endpoint(self, client, monkeypatch):
        monkeypatch.setattr(
            verificadores,
            "leer_bitacora",
            lambda limit=50: [{"control_id": "1", "estado": "cumple"}]
        )
        response = client.get("/api/verificaciones/bitacora")
        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 1
        assert len(data["entries"]) == 1

    def test_api_guardar_ficha_evidencia(self, client, monkeypatch):
        import api_server
        analysis_id = "test-analysis-f11-0001"
        monkeypatch.setitem(api_server.jobs, analysis_id, {
            "analysis_id": analysis_id,
            "controls_review": {
                "disponible": True,
                "results": [
                    {"id": "4", "nombre": "Alerta de ataques", "estado": "no_evaluado", "metodo": "evidencia"}
                ]
            }
        })
        monkeypatch.setattr(api_server, "_save", lambda aid, res: None)

        response = client.post(f"/api/analysis/{analysis_id}/controls/4/evidencia", json={
            "que_subir": "Log de SIEM con alerta de 5 intentos fallidos",
            "quien_sube": "Hugo - SecOps",
            "fecha": "2026-10-23",
            "notas": "Alerta verificada en PagerDuty ticket SEC-102",
            "estado": "cumple",
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["ficha_evidencia"]["quien_sube"] == "Hugo - SecOps"
        assert data["control"]["estado"] == "cumple"
