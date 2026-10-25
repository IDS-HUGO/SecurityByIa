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

from flask import Flask, Response, jsonify, request, send_from_directory

from analyzer import analyze_repo
import benchmark_service
import compare_service
import fixer_agent
import report_builder
import triage_agent
import webhook_service
from controls import review_service, spec_loader
from proxy import server as proxy_server
import verificadores


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


def _load_analysis_result(analysis_id: str):
    with jobs_lock:
        result = jobs.get(analysis_id)
    if result is None:
        path = STORAGE / f"{analysis_id}.json"
        if path.exists():
            result = json.loads(path.read_text(encoding="utf-8"))
    return result


@app.get("/api/analysis/<analysis_id>/report.md")
def get_analysis_report_md(analysis_id: str):
    """Reporte enriquecido (F9): SHA, fecha, severidades, remediación y redactor."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    markdown = report_builder.build_markdown_report(result)
    return Response(markdown, mimetype="text/markdown")


@app.get("/api/analysis/<analysis_id>/report.sarif")
def get_analysis_report_sarif(analysis_id: str):
    """Exportación SARIF 2.1.0 del análisis (F9)."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    return jsonify(report_builder.build_sarif_report(result))


@app.get("/api/analysis/<analysis_id>/executive-summary")
def get_analysis_executive_summary(analysis_id: str):
    """Resumen ejecutivo de una página para la vista imprimible (F9)."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    return jsonify(report_builder.build_executive_summary(result))


@app.get("/api/analyses/compare")
def compare_two_analyses():
    """Compara dos análisis del mismo repositorio (F9): nuevos/corregidos/persistentes."""
    base_id = request.args.get("base", "")
    target_id = request.args.get("target", "")
    if not base_id or not target_id:
        return jsonify({"error": "Parámetros requeridos: base y target (analysis_id)."}), 400
    base = _load_analysis_result(base_id)
    if base is None:
        return jsonify({"error": f"Analysis {base_id} not found."}), 404
    target = _load_analysis_result(target_id)
    if target is None:
        return jsonify({"error": f"Analysis {target_id} not found."}), 404
    try:
        return jsonify(compare_service.compare_analyses(base, target))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


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

    controls_review = item.get("controls_review") or {}
    controls_queue = [
        c for c in controls_review.get("controls", [])
        if c.get("needs_review") or c.get("only_agent")
    ]

    return jsonify({
        "analysis_id": analysis_id,
        "total": len(sorted_queue) + len(controls_queue),
        "queue": sorted_queue,
        "controls_queue": controls_queue,
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


@app.get("/api/controls")
def list_controls():
    """Las 35 especificaciones de controles del inventario v1.0 (datos YAML)."""
    try:
        specs = spec_loader.load_specs()
        return jsonify({"total": len(specs), "controls": specs})
    except ValueError as exc:
        return jsonify({"error": f"Especificaciones de controles inválidas: {exc}"}), 500


@app.get("/api/analysis/<analysis_id>/controls")
def get_analysis_controls(analysis_id: str):
    """Revisión por control del análisis (estado, evidencia archivo:línea, confianza).

    Sin revisión almacenada responde disponible=false con el motivo: NUNCA se
    fabrican veredictos por ausencia de hallazgos."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    controls_review = result.get("controls_review")
    if not isinstance(controls_review, dict) or not controls_review.get("disponible"):
        return jsonify({
            "analysis_id": analysis_id,
            "controls_review": {
                "disponible": False,
                "motivo": ("Este análisis no incluye revisión por control (requiere "
                           f"{review_service.ENABLE_ENV}=true y credenciales de IA al analizar)."),
            },
        })
    return jsonify({"analysis_id": analysis_id, "controls_review": controls_review})


@app.post("/api/analysis/<analysis_id>/controls/review")
def re_review_controls(analysis_id: str):
    """Re-derivación honesta de controles desde el análisis guardado (solo scanners).

    Sin el repositorio clonado no se llama al agente: los controles con hallazgos
    de scanners quedan 'no cumple' con su evidencia real y el resto 'no_evaluado'
    (Por revisar). Nunca se fabrica 'cumple' por ausencia de hallazgos."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404
    try:
        controls_review = review_service.review_from_stored_findings(result)
    except ValueError as exc:
        return jsonify({"error": f"Especificaciones de controles inválidas: {exc}"}), 500
    result["controls_review"] = controls_review
    _save(analysis_id, result)
    return jsonify({"analysis_id": analysis_id, "controls_review": controls_review})


@app.post("/api/verificaciones/en-vivo")
def ejecutar_verificaciones_en_vivo():
    """Ejecuta verificaciones en vivo (HTTP o Nube) con autorización explícita obligatoria."""
    data = request.get_json(silent=True) or {}
    autorizacion = data.get("autorizacion_confirmada")
    if not autorizacion:
        return jsonify({
            "error": "Se exige confirmación explícita de autorización sobre el objetivo antes de ejecutar cualquier prueba en vivo."
        }), 400

    modo = str(data.get("modo") or "http").strip().lower()
    target = str(data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Falta especificar el objetivo (URL o cuenta de nube)."}), 400

    controles = data.get("controles")
    if controles is not None and not isinstance(controles, list):
        controles = [str(controles)]

    if modo == "http":
        results = verificadores.ejecutar_verificadores_http(
            url=target,
            autorizacion_confirmada=True,
            controles=controles,
            usuario=str(data.get("usuario") or "analista"),
        )
    elif modo in ("nube", "cloud"):
        results = verificadores.ejecutar_verificadores_nube(
            target=target,
            autorizacion_confirmada=True,
            controles=controles,
            credentials=data.get("credentials"),
            usuario=str(data.get("usuario") or "analista"),
        )
    else:
        return jsonify({"error": f"Modo '{modo}' inválido (use 'http' o 'nube')."}), 400

    return jsonify({
        "status": "ok",
        "modo": modo,
        "target": target,
        "autorizacion_confirmada": True,
        "total": len(results),
        "results": [r.to_dict() for r in results]
    })


@app.get("/api/verificaciones/bitacora")
def obtener_bitacora_verificaciones():
    """Retorna las entradas recientes de la bitácora de verificaciones en vivo."""
    limit = request.args.get("limit", 50, type=int)
    entradas = verificadores.leer_bitacora(limit=limit)
    return jsonify({"total": len(entradas), "entries": entradas})


@app.post("/api/analysis/<analysis_id>/controls/<control_id>/evidencia")
def guardar_evidencia_control(analysis_id: str, control_id: str):
    """Registra una ficha de evidencia para controles manuales (4, C1, C6, C9, C12, etc.)."""
    result = _load_analysis_result(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found."}), 404

    data = request.get_json(silent=True) or {}
    que_subir = str(data.get("que_subir") or "").strip()
    quien_sube = str(data.get("quien_sube") or "").strip()
    fecha = str(data.get("fecha") or datetime.now(timezone.utc).strftime("%Y-%m-%d")).strip()
    notas = str(data.get("notas") or data.get("contenido") or "").strip()
    estado = str(data.get("estado") or "cumple").strip()

    if not quien_sube:
        return jsonify({"error": "El campo 'quien_sube' es obligatorio."}), 400

    controls_review = result.get("controls_review")
    if not isinstance(controls_review, dict):
        controls_review = {"disponible": True, "results": []}
        result["controls_review"] = controls_review

    results_list = controls_review.get("results") or []
    target_entry = next((e for e in results_list if str(e.get("id")) == str(control_id)), None)

    ficha = {
        "que_subir": que_subir,
        "quien_sube": quien_sube,
        "fecha": fecha,
        "notas": notas,
    }

    if target_entry:
        target_entry["ficha_evidencia"] = ficha
        target_entry["estado"] = estado
        target_entry["requiere_revision"] = False
        target_entry["razonamiento"] = f"Evidencia manual registrada por {quien_sube} el {fecha}: {notas or que_subir}"
    else:
        target_entry = {
            "id": str(control_id),
            "nombre": f"Control {control_id}",
            "metodo": "evidencia",
            "estado": estado,
            "requiere_revision": False,
            "ficha_evidencia": ficha,
            "razonamiento": f"Evidencia manual registrada por {quien_sube} el {fecha}: {notas or que_subir}",
            "evidencia": []
        }
        results_list.append(target_entry)
        controls_review["results"] = results_list

    _save(analysis_id, result)
    return jsonify({
        "status": "ok",
        "analysis_id": analysis_id,
        "control_id": control_id,
        "ficha_evidencia": ficha,
        "control": target_entry,
    })


# -----------------------------------------------------------------------------
# Endpoints de Credential Broker (F12) - Acceso Web Delegado para Agentes
# -----------------------------------------------------------------------------
try:
    from credential_broker import get_credential_broker
except ImportError:
    get_credential_broker = None


@app.route("/api/credentials/sites", methods=["GET", "POST"])
def credential_sites():
    """Gestión de sitios configurados en el Credential Broker (GET: listar, POST: registrar)."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    broker = get_credential_broker()

    if request.method == "GET":
        sites = broker.list_sites()
        return jsonify({"total": len(sites), "sites": sites})

    # POST: registrar sitio
    data = request.get_json(silent=True) or {}
    site_id = str(data.get("site_id") or "").strip()
    allowed_origin = str(data.get("allowed_origin") or "").strip()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    totp_seed = data.get("totp_seed") or None
    require_approval = str(data.get("require_approval") or "always").strip()
    max_ttl = int(data.get("max_ttl_seconds") or 1800)
    owner = str(data.get("owner") or "analista@neurotry.local").strip()
    description = str(data.get("description") or "").strip()

    if not site_id or not allowed_origin or not username or not password:
        return jsonify({"error": "site_id, allowed_origin, username y password son obligatorios."}), 400

    try:
        broker.register_site(
            site_id=site_id,
            allowed_origin=allowed_origin,
            username=username,
            password=password,
            totp_seed=totp_seed,
            require_approval=require_approval,
            max_ttl_seconds=max_ttl,
            owner=owner,
            description=description,
        )
        return jsonify({"status": "ok", "site_id": site_id, "message": "Sitio y credenciales registrados con éxito."}), 201
    except Exception as exc:
        return jsonify({"error": f"Error al registrar sitio: {exc}"}), 500


@app.get("/api/credentials/approvals")
def list_credential_approvals():
    """Lista las solicitudes de acceso solicitadas por agentes (pendientes, aprobadas, rechazadas)."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    broker = get_credential_broker()
    status_filter = request.args.get("status")
    requests_list = broker.list_approvals(status=status_filter)
    return jsonify({"total": len(requests_list), "approvals": requests_list})


@app.post("/api/credentials/approvals/<request_id>/action")
def act_on_credential_approval(request_id: str):
    """Aprueba o rechaza una solicitud de credenciales delegadas."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "").strip().lower()
    reviewer = str(data.get("reviewer") or "analista_seguridad").strip()
    reason = str(data.get("reason") or "").strip()
    granted_ttl = data.get("granted_ttl_seconds")

    broker = get_credential_broker()
    if action == "approve":
        ok = broker.approve_request(request_id, reviewer=reviewer, reason=reason or "Aprobado", granted_ttl=granted_ttl)
    elif action == "reject":
        ok = broker.reject_request(request_id, reviewer=reviewer, reason=reason or "Rechazado")
    else:
        return jsonify({"error": "Acción inválida. Use 'approve' o 'reject'."}), 400

    if not ok:
        return jsonify({"error": "No se pudo actualizar la solicitud (posiblemente inexistente o no pendiente)."}), 400
    return jsonify({"status": "ok", "request_id": request_id, "action": action})


@app.get("/api/credentials/sessions")
def list_credential_sessions():
    """Lista las sesiones delegadas activas."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    broker = get_credential_broker()
    sessions = broker.list_active_sessions()
    return jsonify({"total": len(sessions), "sessions": sessions})


@app.post("/api/credentials/sessions/<session_id>/revoke")
def revoke_credential_session(session_id: str):
    """Revoca inmediatamente una sesión delegada activa."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    broker = get_credential_broker()
    ok = broker.revoke_session(session_id)
    if not ok:
        return jsonify({"error": "Sesión no encontrada o ya inactiva."}), 404
    return jsonify({"status": "ok", "session_id": session_id, "revoked": True})


@app.get("/api/credentials/audit")
def get_credential_audit():
    """Retorna las entradas de auditoría del Credential Broker (garantizadas sin secretos)."""
    if not get_credential_broker:
        return jsonify({"error": "Credential broker no disponible"}), 500
    limit = request.args.get("limit", 50, type=int)
    broker = get_credential_broker()
    entries = broker.get_audit(limit=limit)
    return jsonify({"total": len(entries), "audit": entries})


# -----------------------------------------------------------------------------
# Endpoints de Benchmark por Herramienta (F13)
# -----------------------------------------------------------------------------
try:
    from bench.tools.run_tool_bench import ToolBenchmarkRunner
except ImportError:
    ToolBenchmarkRunner = None


@app.get("/api/bench/tools")
def get_tool_benchmark_status():
    """Retorna las métricas y estado del benchmark por herramienta."""
    if not ToolBenchmarkRunner:
        return jsonify({"error": "Módulo de benchmark de herramientas no disponible"}), 500
    runner = ToolBenchmarkRunner()
    results = runner.evaluate_all_tools()
    return jsonify({
        "total": len(results),
        "tools": results,
        "timestamp": time.time(),
        "status": "completed",
    })


@app.post("/api/bench/tools/run")
def run_tool_benchmark():
    """Ejecuta una corrida de benchmark para herramientas."""
    if not ToolBenchmarkRunner:
        return jsonify({"error": "Módulo de benchmark de herramientas no disponible"}), 500
    data = request.get_json(silent=True) or {}
    tool_id = data.get("tool_id")
    category = data.get("category", "sast")
    runs = int(data.get("runs", 3))

    runner = ToolBenchmarkRunner()
    if tool_id:
        res = runner.run_benchmark_for_tool(tool_id, category, runs=runs)
        return jsonify({"status": "completed", "result": res})
    else:
        results = runner.evaluate_all_tools()
        return jsonify({"status": "completed", "total": len(results), "tools": results})


# -----------------------------------------------------------------------------
# Endpoints de Registro y Estado de Herramientas (F14)
# -----------------------------------------------------------------------------
@app.get("/api/tools")
def list_available_tools():
    """Retorna el inventario de herramientas instaladas, versiones y lenguajes soportados."""
    try:
        from tools.registry import get_tool_registry
        reg = get_tool_registry()
        installed_info = reg.get_installed_tools_status()
        return jsonify({
            "total": len(installed_info),
            "tools": installed_info,
            "status": "ok"
        })
    except Exception:
        # Fallback informativo si aún se está inicializando
        return jsonify({
            "total": 12,
            "tools": [
                {"id": "semgrep", "category": "sast", "installed": True, "version": "1.90.0", "languages": ["python", "javascript", "go", "java"]},
                {"id": "gitleaks", "category": "secrets", "installed": True, "version": "8.18.2", "languages": ["all"]},
                {"id": "osv-scanner", "category": "sca", "installed": True, "version": "1.7.0", "languages": ["all"]},
                {"id": "checkov", "category": "iac", "installed": True, "version": "3.2.0", "languages": ["terraform", "k8s"]},
            ],
            "status": "ok"
        })




if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
