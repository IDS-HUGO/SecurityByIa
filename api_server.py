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


ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage" / "analyses"
STORAGE.mkdir(parents=True, exist_ok=True)
GITHUB_URL = re.compile(r"^https?://github\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$")


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
app = Flask(__name__, static_folder="static")

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


def _run_analysis(analysis_id: str, url: str) -> None:
    def update(stage: str, percentage: int, message: str) -> None:
        with jobs_lock:
            jobs[analysis_id].update({"stage": stage, "progress": percentage, "message": message})

    try:
        result = analyze_repo(url, update)
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
    return send_from_directory(app.static_folder, "index.html")


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
    analysis_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[analysis_id] = {
            "analysis_id": analysis_id,
            "status": "processing",
            "stage": "queued",
            "progress": 0,
            "message": "Analysis queued",
            "repository": {"url": url.strip()},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    analysis_executor.submit(_run_analysis, analysis_id, url.strip())
    return jsonify({
        "analysis_id": analysis_id,
        "status": "processing",
        "stage": "queued",
        "progress": 0,
        "message": "Analysis queued",
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


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
