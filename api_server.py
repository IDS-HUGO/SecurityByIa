"""Flask API for the repository security dashboard."""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request, send_from_directory

from analyzer import analyze_repo


ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage" / "analyses"
STORAGE.mkdir(parents=True, exist_ok=True)
GITHUB_URL = re.compile(r"^https?://github\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$")
jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()
app = Flask(__name__, static_folder="static")


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
    except RuntimeError as exc:
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
    thread = threading.Thread(target=_run_analysis, args=(analysis_id, url.strip()), daemon=True)
    thread.start()
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
