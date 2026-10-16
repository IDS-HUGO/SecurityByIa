"""OpenAPI Contract Tests:
Validates that backend/openapi.yaml accurately matches all Flask API endpoints,
HTTP methods, and response schemas.
"""

from pathlib import Path
import re
import pytest
import yaml

from api_server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def openapi_spec():
    spec_path = Path(__file__).resolve().parents[1] / "openapi.yaml"
    assert spec_path.is_file(), f"openapi.yaml not found at {spec_path}"
    with open(spec_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "openapi.yaml must be a valid dictionary"
    return data


def test_openapi_spec_structure(openapi_spec):
    """Verify OpenAPI 3.0 basic structure and metadata."""
    assert openapi_spec.get("openapi", "").startswith("3.0")
    assert "info" in openapi_spec
    assert "title" in openapi_spec["info"]
    assert "version" in openapi_spec["info"]
    assert "paths" in openapi_spec
    assert "components" in openapi_spec


def test_all_flask_api_routes_documented_in_openapi(openapi_spec):
    """Verify that every Flask endpoint starting with /api/ is declared in openapi.yaml."""
    openapi_paths = set(openapi_spec["paths"].keys())

    # Map Flask route syntax /api/analysis/<analysis_id> to OpenAPI /api/analysis/{analysis_id}
    flask_api_routes = set()
    for rule in app.url_map.iter_rules():
        rule_str = str(rule.rule)
        if rule_str.startswith("/api/"):
            normalized = re.sub(r"<([^>]+)>", r"{\1}", rule_str)
            flask_api_routes.add(normalized)

    # Every Flask route must exist in OpenAPI paths
    for route in flask_api_routes:
        assert route in openapi_paths, f"Flask route {route} is missing from openapi.yaml"


def test_all_openapi_paths_exist_in_flask(openapi_spec):
    """Verify that every path documented in openapi.yaml exists in Flask."""
    flask_normalized_routes = set()
    for rule in app.url_map.iter_rules():
        rule_str = str(rule.rule)
        normalized = re.sub(r"<([^>]+)>", r"{\1}", rule_str)
        flask_normalized_routes.add(normalized)

    for path in openapi_spec["paths"]:
        assert path in flask_normalized_routes, f"OpenAPI path {path} does not exist in Flask app"


def test_http_methods_match(openapi_spec):
    """Verify that HTTP methods declared in OpenAPI match Flask url_map rules."""
    flask_route_methods = {}
    for rule in app.url_map.iter_rules():
        rule_str = str(rule.rule)
        if rule_str.startswith("/api/"):
            normalized = re.sub(r"<([^>]+)>", r"{\1}", rule_str)
            methods = {m.lower() for m in rule.methods if m not in ("HEAD", "OPTIONS")}
            flask_route_methods[normalized] = methods

    for path, path_item in openapi_spec["paths"].items():
        spec_methods = {m.lower() for m in path_item.keys() if m in ("get", "post", "put", "delete", "patch")}
        flask_methods = flask_route_methods.get(path, set())
        assert spec_methods == flask_methods, f"Method mismatch on {path}: spec={spec_methods}, flask={flask_methods}"


def test_contract_responses(client):
    """Verify API responses against expected contract status codes and schemas."""
    # 1. Spec availability
    spec_res = client.get("/openapi.yaml")
    assert spec_res.status_code == 200
    assert "openapi: 3.0" in spec_res.get_data(as_text=True)

    # 2. JSON root health
    root_res = client.get("/")
    assert root_res.status_code == 200
    assert root_res.is_json
    assert root_res.json.get("status") == "healthy"

    # 3. GET /api/analyses
    analyses_res = client.get("/api/analyses")
    assert analyses_res.status_code == 200
    assert isinstance(analyses_res.json, list)

    # 4. GET /api/bench
    bench_res = client.get("/api/bench")
    assert bench_res.status_code == 200
    assert "status" in bench_res.json
    assert "history" in bench_res.json

    # 5. GET /api/analysis/<id> not found
    not_found_res = client.get("/api/analysis/00000000-0000-0000-0000-000000000000")
    assert not_found_res.status_code == 404
    assert "error" in not_found_res.json

    # 6. POST /api/analyze invalid URL
    bad_scan = client.post("/api/analyze", json={"url": "not-a-github-url"})
    assert bad_scan.status_code == 400
    assert "error" in bad_scan.json

    # 7. POST /api/bench/run invalid body
    bad_bench = client.post("/api/bench/run", json={"feature": 12345})
    assert bad_bench.status_code == 400
    assert "error" in bad_bench.json
