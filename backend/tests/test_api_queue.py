"""Pruebas pytest de la cola de análisis y del límite por IP en la API Flask.

Cubren: 429 por exceder el límite de solicitudes por IP, cola con máximo N
análisis simultáneos (los excedentes quedan en stage "queued" hasta liberarse
un worker) y sobrevivencia del historial leyendo storage/analyses/ tras un
reinicio (los trabajos en vuelo se marcan como interrumpidos).

Ninguna prueba ejecuta un análisis real: _run_analysis se sustituye por stubs.

Ejecución:
    python -m pytest tests/test_api_queue.py -v
"""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import api_server


@pytest.fixture()
def clean_jobs():
    saved_jobs = dict(api_server.jobs)
    api_server.jobs.clear()
    yield
    api_server.jobs.clear()
    api_server.jobs.update(saved_jobs)


@pytest.fixture()
def clean_rate_limits():
    api_server._rate_hits.clear()
    yield
    api_server._rate_hits.clear()


def test_rate_limit_returns_429(monkeypatch, clean_jobs, clean_rate_limits):
    monkeypatch.setattr(api_server, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(api_server, "_run_analysis", lambda *args, **kwargs: None)
    client = api_server.app.test_client()
    url = "https://github.com/acme/repo"

    assert client.post("/api/analyze", json={"url": url}).status_code == 202
    assert client.post("/api/analyze", json={"url": url}).status_code == 202
    third = client.post("/api/analyze", json={"url": url})
    assert third.status_code == 429
    assert "IP" in third.get_json()["error"]


def test_bench_run_rate_limited(monkeypatch, clean_rate_limits):
    monkeypatch.setattr(api_server, "RATE_LIMIT_PER_MINUTE", 0)
    client = api_server.app.test_client()
    response = client.post("/api/bench/run", json={})
    assert response.status_code == 429
    assert "IP" in response.get_json()["error"]


def test_queue_limits_concurrency(monkeypatch, clean_jobs):
    release = threading.Event()
    started_ids = []

    def blocking_analysis(analysis_id, url):
        # El análisis real actualiza el stage con su primer callback de progreso;
        # el stub refleja que el worker lo tomó.
        with api_server.jobs_lock:
            api_server.jobs[analysis_id]["stage"] = "cloning"
        started_ids.append(analysis_id)
        release.wait(timeout=5)

    limited_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-pool")
    monkeypatch.setattr(api_server, "analysis_executor", limited_pool)
    monkeypatch.setattr(api_server, "_run_analysis", blocking_analysis)

    client = api_server.app.test_client()
    url = "https://github.com/acme/repo"
    try:
        ids = [
            client.post("/api/analyze", json={"url": url}).get_json()["analysis_id"]
            for _ in range(3)
        ]

        # Los dos primeros ocupan los dos workers; el tercero espera en cola.
        for _ in range(200):
            if len(started_ids) >= 2:
                break
            time.sleep(0.02)
        assert len(started_ids) == 2

        with api_server.jobs_lock:
            stages = {jid: api_server.jobs[jid]["stage"] for jid in ids}
        assert list(stages.values()).count("queued") == 1
        assert sum(1 for stage in stages.values() if stage != "queued") == 2
    finally:
        release.set()
        limited_pool.shutdown(wait=False)

    for _ in range(200):
        if len(started_ids) == 3:
            break
        time.sleep(0.02)
    assert len(started_ids) == 3, "el trabajo en cola debe ejecutarse al liberarse un worker"


def test_history_survives_restart(tmp_path, monkeypatch, clean_jobs):
    storage = tmp_path / "analyses"
    storage.mkdir()

    (storage / "a-ok.json").write_text(json.dumps({
        "analysis_id": "a-ok",
        "status": "completed",
        "summary": {"total": 3},
        "repository": {"url": "https://github.com/acme/ok"},
    }), encoding="utf-8")
    (storage / "a-stuck.json").write_text(json.dumps({
        "analysis_id": "a-stuck",
        "status": "processing",
        "stage": "cloning",
        "progress": 35,
        "repository": {"url": "https://github.com/acme/stuck"},
    }), encoding="utf-8")

    monkeypatch.setattr(api_server, "STORAGE", storage)
    api_server._load_analyses_from_storage()

    ok = api_server.jobs["a-ok"]
    stuck = api_server.jobs["a-stuck"]
    assert ok["status"] == "completed", "el historial completado se conserva intacto"
    assert stuck["status"] == "error"
    assert stuck["stage"] == "failed"
    assert "reinicio" in stuck["error_message"]

    on_disk = json.loads((storage / "a-stuck.json").read_text(encoding="utf-8"))
    assert on_disk["status"] == "error", "el archivo persistido refleja la interrupción"
