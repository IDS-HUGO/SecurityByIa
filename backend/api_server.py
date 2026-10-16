"""Flask API for the repository security dashboard."""

import json
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory

from analyzer import analyze_repo
import benchmark_service
import fixer_agent
import triage_agent
import webhook_service
from proxy import server as proxy_server


ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage" / "analyses"
STORAGE.mkdir(parents=True, exist_ok=True)
GITHUB_URL = re.compile(r"^https?://github\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
WEBHOOK_MAX_BODY_BYTES = 1_000_000


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


MAX_CONCURRENT_ANALYSES = _env_int("MAX_CONCURRENT_ANALYSES", 2)
RATE_LIMIT_PER_MINUTE = _env_int("RATE_LIMIT_PER_MINUTE", 30)
RATE_LIMIT_WINDOW_SECONDS = 60

jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()
app = Flask(__name__)


def _get_allowed_cors_origins() -> set:
    raw = os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    return {origin.strip() for origin in raw.split(",") if origin.strip()}


@app.before_request
def _handle_cors_preflight():
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin")
        allowed = _get_allowed_cors_origins()
        if origin and origin in allowed:
            resp = app.make_default_options_response()
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            resp.headers["Access-Control-Max-Age"] = "86400"
            resp.headers["Vary"] = "Origin"
            return resp
        return ("", 204)


@app.after_request
def _apply_cors_headers(response):
    origin = request.headers.get("Origin")
    allowed = _get_allowed_cors_origins()
    if origin and origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        response.headers["Vary"] = "Origin"
    return response

# Bounded analysis queue: at most MAX_CONCURRENT_ANALYSES run at once,
# extra requests wait queued in the pool's FIFO.
analysis_executor = ThreadPoolExecutor(
    max_workers=MAX_CONCURRENT_ANALYSES,
    thread_name_prefix="sast-analysis",
)

# In-memory sliding-window rate limiter per IP (applied to POST endpoints).
_rate_limit_lock = threading.Lock()
_rate_hits: Dict[str, List[float]] = {}


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _rate_limit_exceeded(ip: str) -> bool:
    now = time.monotonic()
    with _rate_limit_lock:
        hits = [stamp for stamp in _rate_hits.get(ip, []) if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
        if len(hits) >= RATE_LIMIT_PER_MINUTE:
            _rate_hits[ip] = hits
            return True
        hits.append(now)
        _rate_hits[ip] = hits
        return False


def _load_analyses_from_storage() -> None:
    """Load persisted analyses so history survives restarts. Jobs that were in
    flight when the process died are marked as interrupted instead of hanging."""
    with jobs_lock:
        for path in sorted(STORAGE.glob("*.json")):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            analysis_id = str(item.get("analysis_id") or path.stem)
            if item.get("status") in ("processing", "running", "queued"):
                item["status"] = "error"
                item["stage"] = "failed"
                item["progress"] = 100
                item["message"] = "Analysis failed"
                item["error_message"] = (
                    "Análisis interrumpido por un reinicio del servidor. Reintentá el escaneo."
                )
                try:
                    (STORAGE / f"{analysis_id}.json").write_text(
                        json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                except OSError:
                    pass
            jobs[analysis_id] = item


_load_analyses_from_storage()


def _save(analysis_id: str, value: Dict[str, Any]) -> None:
    target = STORAGE / f"{analysis_id}.json"
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_analysis(analysis_id: str, url: str, enable_ai_triage: bool = False) -> None:
    def update(stage: str, percentage: int, message: str) -> None:
        with jobs_lock:
            jobs[analysis_id].update({"stage": stage, "progress": percentage, "message": message})

    try:
        result = analyze_repo(url, update, enable_ai_triage=enable_ai_triage)
        result.update({"analysis_id": analysis_id, "created_at": jobs[analysis_id]["created_at"]})
        with jobs_lock:
            jobs[analysis_id] = result
        _save(analysis_id, result)
    except Exception as exc:  # un pool traga excepciones no capturadas: persistimos el fallo
        error = {
            "analysis_id": analysis_id,
            "status": "error",
            "stage": "failed",
            "progress": 100,
            "message": "Analysis failed",
            "error_message": str(exc),
            "repository": {"url": url},
            "created_at": jobs[analysis_id]["created_at"],
        }
        with jobs_lock:
            jobs[analysis_id] = error
        _save(analysis_id, error)


@app.get("/")
def index():
    return jsonify({
        "service": "Security Control Center API",
        "status": "healthy",
        "version": "1.0.0",
        "openapi": "/openapi.yaml",
    })


@app.get("/openapi.yaml")
def openapi_spec():
    spec_path = ROOT / "openapi.yaml"
    if spec_path.is_file():
        return spec_path.read_text(encoding="utf-8"), 200, {"Content-Type": "application/yaml"}
    return jsonify({"error": "OpenAPI contract not found."}), 404


@app.post("/api/analyze")
def start_analysis():
    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")
    if not isinstance(url, str) or not GITHUB_URL.fullmatch(url.strip()):
        return jsonify({"error": "Enter a valid public GitHub repository URL."}), 400
    enable_ai_triage = bool(body.get("enable_ai_triage", False))
    analysis_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[analysis_id] = {
            "analysis_id": analysis_id,
            "status": "processing",
            "stage": "queued",
            "progress": 0,
            "message": "Analysis queued",
            "repository": {"url": url.strip()},
            "enable_ai_triage": enable_ai_triage,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    if enable_ai_triage:
        analysis_executor.submit(_run_analysis, analysis_id, url.strip(), enable_ai_triage)
    else:
        analysis_executor.submit(_run_analysis, analysis_id, url.strip())
    return jsonify({
        "analysis_id": analysis_id,
        "status": "processing",
        "stage": "queued",
        "progress": 0,
        "message": "Analysis queued",
        "enable_ai_triage": enable_ai_triage,
    }), 202


@app.get("/api/analysis/<analysis_id>")
def get_analysis(analysis_id: str):
    with jobs_lock:
        result = jobs.get(analysis_id)
    if result is None:
        path = STORAGE / f"{analysis_id}.json"
        if path.exists():
            result = json.loads(path.read_text(encoding="utf-8"))
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    return jsonify(result)


@app.get("/api/analyses")
def list_analyses():
    results = []
    for path in sorted(STORAGE.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            results.append({
                "analysis_id": item.get("analysis_id", path.stem),
                "status": item.get("status"),
                "stage": item.get("stage"),
                "created_at": item.get("created_at"),
                "repository": item.get("repository"),
                "summary": item.get("summary"),
            })
        except json.JSONDecodeError:
            continue
    return jsonify(results[:20])


@app.get("/api/bench")
def get_bench():
    """Return status of benchmark engine, latest run, baseline, and history."""
    return jsonify(benchmark_service.get_benchmark_status())


@app.post("/api/bench/run")
def run_bench():
    """Trigger a single benchmark run, reusing the analysis engine."""
    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "El cuerpo de la petición debe ser un objeto JSON."}), 400
    feature = body.get("feature")
    if feature is not None and not isinstance(feature, str):
        return jsonify({"error": "'feature' debe ser una cadena de texto."}), 400
    save_as_baseline = bool(body.get("save_as_baseline", False))
    try:
        result = benchmark_service.start_benchmark_run_async(
            feature_name=feature,
            save_as_baseline=save_as_baseline,
        )
        return jsonify(result), 202
    except RuntimeError as exc:
        return jsonify({
            "error": str(exc),
            "status": "running",
            "message": "Ya hay una corrida de benchmark en ejecución.",
        }), 409


@app.get("/api/bench/baseline")
def get_bench_baseline():
    """Return current baseline benchmark report."""
    baseline = benchmark_service.get_baseline()
    if not baseline:
        return jsonify({"error": "No baseline benchmark run found."}), 404
    return jsonify(baseline)


@app.get("/api/bench/history")
def get_bench_history():
    """Return list of previous benchmark runs."""
    return jsonify(benchmark_service.get_history())


@app.get("/api/bench/run/<run_id>")
def get_bench_run(run_id: str):
    """Return specific benchmark run by ID."""
    run_file = ROOT / "storage" / "benchmark" / "runs" / f"{run_id}.json"
    if not run_file.exists():
        return jsonify({"error": f"Benchmark run '{run_id}' not found."}), 404
    try:
        return jsonify(json.loads(run_file.read_text(encoding="utf-8")))
    except Exception as exc:
        return jsonify({"error": f"Error reading benchmark file: {exc}"}), 500


@app.post("/api/analysis/<analysis_id>/finding/<finding_id>/triage")
def triage_finding(analysis_id: str, finding_id: str):
    """Register a human triage decision (verdadero, falso, incierto) with mandatory reason."""
    try:
        f_id = int(finding_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Identificador de hallazgo inválido."}), 400

    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429

    body = request.get_json(silent=True) or {}
    decision = str(body.get("decision") or "").strip().lower()
    if decision not in ("verdadero", "falso", "incierto"):
        return jsonify({
            "error": "Veredicto inválido. Debe ser 'verdadero', 'falso' o 'incierto'.",
        }), 400

    reason = str(body.get("reason") or "").strip()
    if not reason or len(reason) < 3:
        return jsonify({
            "error": "El motivo es obligatorio para registrar la decisión de triage.",
        }), 400

    author = str(body.get("author") or "analista-seguridad").strip()

    with jobs_lock:
        item = jobs.get(analysis_id)
        if item is None:
            path = STORAGE / f"{analysis_id}.json"
            if path.exists():
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                    jobs[analysis_id] = item
                except Exception:
                    pass

        if item is None:
            return jsonify({"error": "Analysis not found."}), 404

        findings = item.get("findings", [])
        target_finding = next((f for f in findings if f.get("id") == f_id), None)
        if not target_finding:
            return jsonify({"error": f"Finding with id {f_id} not found."}), 404

        timestamp = datetime.now(timezone.utc).isoformat()
        target_finding["triage"] = {
            "verdict": decision,
            "confidence": 1.0,
            "reason": reason,
            "decided_by": "persona",
            "author": author,
            "timestamp": timestamp,
        }

        fp_hash = None
        if decision == "falso":
            target_finding["false_positive"] = True
            target_finding["status"] = "false_positive"
            target_finding["needs_human_review"] = False
            ctx = target_finding.get("code_context") or []
            snippet = "\n".join(c.get("text", "") for c in ctx) or target_finding.get("code", "")
            fp_hash = triage_agent.save_false_positive_fingerprint(
                file_path=target_finding.get("file", ""),
                rule=target_finding.get("rule", ""),
                code_snippet=snippet,
                reason=reason,
                author=author,
            )
            target_finding["triage"]["fingerprint"] = fp_hash
        elif decision == "verdadero":
            target_finding["false_positive"] = False
            target_finding["status"] = "confirmed"
            target_finding["needs_human_review"] = False
        elif decision == "incierto":
            target_finding["needs_human_review"] = True

        _save(analysis_id, item)

    return jsonify({
        "status": "success",
        "analysis_id": analysis_id,
        "finding": target_finding,
        "fingerprint": fp_hash,
    })


@app.get("/api/analysis/<analysis_id>/review-queue")
def get_review_queue(analysis_id: str):
    """Return findings needing human review (uncertain / marked for review) ordered by severity."""
    with jobs_lock:
        item = jobs.get(analysis_id)
        if item is None:
            path = STORAGE / f"{analysis_id}.json"
            if path.exists():
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    pass
    if item is None:
        return jsonify({"error": "Analysis not found."}), 404

    findings = item.get("findings", [])
    uncertain_findings = [
        f for f in findings
        if f.get("triage", {}).get("verdict") == "incierto" or f.get("needs_human_review") is True
    ]

    severity_weights = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_queue = sorted(
        uncertain_findings,
        key=lambda f: (severity_weights.get(str(f.get("severity", "low")).lower(), 4), f.get("id", 0)),
    )

    return jsonify({
        "analysis_id": analysis_id,
        "total": len(sorted_queue),
        "queue": sorted_queue,
    })


@app.get("/api/triage/fingerprints")
def get_triage_fingerprints():
    """Return persistent human false positive fingerprints."""
    return jsonify(triage_agent.load_known_false_positive_fingerprints())


@app.post("/api/analysis/<analysis_id>/finding/<finding_id>/fix")
def propose_and_verify_fix(analysis_id: str, finding_id: str):
    """Generate and verify an automated patch for the specified finding."""
    try:
        f_id = int(finding_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Identificador de hallazgo inválido."}), 400

    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429

    with jobs_lock:
        item = jobs.get(analysis_id)
        if item is None:
            path = STORAGE / f"{analysis_id}.json"
            if path.exists():
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                    jobs[analysis_id] = item
                except Exception:
                    pass

        if item is None:
            return jsonify({"error": "Analysis not found."}), 404

        findings = item.get("findings", [])
        target_finding = next((f for f in findings if f.get("id") == f_id), None)
        if not target_finding:
            return jsonify({"error": f"Finding with id {f_id} not found."}), 404

        # Generate patch using deterministic template
        patch = fixer_agent.create_patch_for_finding(target_finding, root_dir="")
        if not patch:
            # Check if finding already has existing remediation with diff
            existing_rem = target_finding.get("remediation")
            if existing_rem and existing_rem.get("diff"):
                return jsonify({
                    "status": "success",
                    "analysis_id": analysis_id,
                    "finding": target_finding,
                    "remediation": existing_rem,
                })
            return jsonify({
                "error": "No se encontró un patrón de corrección automatizada aplicable para este hallazgo.",
                "remediation": target_finding.get("remediation"),
            }), 422

        # Verify patch
        verified_res = fixer_agent.verify_and_apply_patch("", target_finding, patch)
        target_finding["remediation"] = verified_res
        _save(analysis_id, item)

    return jsonify({
        "status": "success",
        "analysis_id": analysis_id,
        "finding": target_finding,
        "remediation": target_finding["remediation"],
    })


@app.post("/api/analysis/<analysis_id>/finding/<finding_id>/remediation/review")
def review_remediation(analysis_id: str, finding_id: str):
    """Record human approval or rejection of a proposed patch with mandatory reason."""
    try:
        f_id = int(finding_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Identificador de hallazgo inválido."}), 400

    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429

    body = request.get_json(silent=True) or {}
    decision = str(body.get("decision") or "").strip().lower()
    if decision not in ("approved", "rejected", "aprobar", "rechazar"):
        return jsonify({
            "error": "Decisión inválida. Debe ser 'approved' o 'rejected'.",
        }), 400

    reason = str(body.get("reason") or "").strip()
    if not reason or len(reason) < 3:
        return jsonify({
            "error": "El motivo es obligatorio para aprobar o rechazar un parche.",
        }), 400

    author = str(body.get("author") or "analista-seguridad").strip()

    with jobs_lock:
        item = jobs.get(analysis_id)
        if item is None:
            path = STORAGE / f"{analysis_id}.json"
            if path.exists():
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                    jobs[analysis_id] = item
                except Exception:
                    pass

        if item is None:
            return jsonify({"error": "Analysis not found."}), 404

        findings = item.get("findings", [])
        target_finding = next((f for f in findings if f.get("id") == f_id), None)
        if not target_finding:
            return jsonify({"error": f"Finding with id {f_id} not found."}), 404

        try:
            fixer_agent.record_human_remediation_review(target_finding, decision, reason, author)
        except ValueError as err:
            return jsonify({"error": str(err)}), 400

        _save(analysis_id, item)

    return jsonify({
        "status": "success",
        "analysis_id": analysis_id,
        "finding": target_finding,
        "remediation": target_finding.get("remediation"),
    })


@app.post("/api/analysis/<analysis_id>/tests/run")
def run_project_sandbox_tests(analysis_id: str):
    """Run analyzed project's own tests strictly in networkless container with opt-in and own-repo."""
    if _rate_limit_exceeded(_client_ip()):
        return jsonify({
            "error": "Demasiadas solicitudes desde tu IP. Esperá un momento y reintentá.",
        }), 429

    body = request.get_json(silent=True) or {}
    opt_in = bool(body.get("opt_in", False))
    is_own_repo = bool(body.get("is_own_repo", False))

    if not (opt_in and is_own_repo):
        return jsonify({
            "error": "Las pruebas del proyecto analizado solo corren en repositorios propios con opt-in explícito.",
            "executed": False,
            "status": "skipped",
        }), 403

    result = fixer_agent.run_project_tests_in_sandbox(
        repo_dir=str(ROOT),
        opt_in=opt_in,
        is_own_repo=is_own_repo,
    )
    return jsonify(result), 200


@app.get("/api/proxy/audit")
def get_proxy_audit():
    """Últimas entradas de auditoría del proxy de secretos: fecha, servicio,
    ruta, resultado y token. Nunca incluye valores secretos ni cuerpos."""
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    return jsonify(proxy_server.read_audit_entries(limit))


@app.get("/api/proxy/status")
def get_proxy_status():
    """Indicador del estado del proxy: configurado, alcanzable, token y
    proveedores en la lista blanca."""
    return jsonify(proxy_server.status_snapshot())


@app.post("/webhooks/github")
def github_webhook():
    """Recibe eventos de GitHub: valida la firma HMAC-SHA256 en tiempo constante,
    salta SHAs ya analizados y encola el análisis del PR restringido a los
    archivos modificados, publicando comentario y check run si hay token."""
    raw_body = request.get_data()
    if len(raw_body) > WEBHOOK_MAX_BODY_BYTES:
        return jsonify({"error": "Payload de webhook demasiado grande."}), 413
    if not GITHUB_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook no configurado: falta GITHUB_WEBHOOK_SECRET."}), 503
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not webhook_service.verify_signature(GITHUB_WEBHOOK_SECRET, signature, raw_body):
        return jsonify({"error": "Firma de webhook inválida."}), 403
    try:
        payload = json.loads(raw_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return jsonify({"error": "Payload JSON inválido."}), 400
    if not isinstance(payload, dict):
        return jsonify({"error": "Payload JSON inválido."}), 400

    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return jsonify({"status": "pong"}), 200
    if event != "pull_request":
        return jsonify({"status": "ignored", "event": event}), 200
    if payload.get("action") not in ("opened", "synchronize", "reopened"):
        return jsonify({"status": "ignored", "action": payload.get("action")}), 200

    pr = webhook_service.extract_pr_payload(payload)
    if not pr:
        return jsonify({"error": "Payload de pull_request incompleto."}), 400

    analysis_id = str(uuid.uuid4())
    claimed, existing = webhook_service.claim_sha(pr["full_name"], pr["head_sha"], {
        "analysis_id": analysis_id,
        "pull_request": pr["number"],
        "repository": pr["full_name"],
        "head_sha": pr["head_sha"],
        "status": "processing",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    if not claimed:
        return jsonify({
            "status": "skipped",
            "reason": "sha-already-analyzed",
            "analysis_id": (existing or {}).get("analysis_id"),
        }), 200

    with jobs_lock:
        jobs[analysis_id] = {
            "analysis_id": analysis_id,
            "status": "processing",
            "stage": "queued",
            "progress": 0,
            "message": "PR analysis queued",
            "repository": {"url": f"{pr['clone_url']}#pull/{pr['number']}"},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def update(stage: str, percentage: int, message: str) -> None:
        with jobs_lock:
            jobs[analysis_id].update({"stage": stage, "progress": percentage, "message": message})

    analysis_executor.submit(webhook_service.run_pr_analysis_task, pr, analysis_id, update)
    return jsonify({
        "analysis_id": analysis_id,
        "status": "processing",
        "stage": "queued",
        "pr": pr["number"],
        "head_sha": pr["head_sha"],
    }), 202


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
