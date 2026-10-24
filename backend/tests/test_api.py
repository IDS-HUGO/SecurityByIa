"""Pruebas de los endpoints de benchmark de la API Flask.

Cubre GET /api/bench y POST /api/bench/run: passthrough del estado del motor,
202 al lanzar una corrida (reenviando feature y save_as_baseline), 409 con una
corrida ya en curso, defaults sin body y rechazo 400 de cuerpos inválidos para
que la API responda siempre JSON estable.

Las funciones del servicio se sustituyen por stubs: ninguna prueba ejecuta un
benchmark real ni escribe en storage/.

Ejecución:
    python -m unittest discover -s tests -v
"""

import unittest
from unittest.mock import patch

from api_server import app
import benchmark_service


class BenchEndpointsTest(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self._patches = []
        self.addCleanup(self._stop_patches)

    def _stop_patches(self):
        for started in self._patches:
            started.stop()

    def _patch_service(self, name, value):
        started = patch.object(benchmark_service, name, value)
        started.start()
        self._patches.append(started)
        return value

    def test_get_bench_returns_status_json(self):
        status = {
            "status": "idle",
            "is_running": False,
            "progress": 0,
            "latest_run": None,
            "baseline": None,
            "reference_repos_count": 5,
            "history": [],
        }
        self._patch_service("get_benchmark_status", lambda: status)
        response = self.client.get("/api/bench")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), status)

    def test_run_bench_accepts_and_forwards_body(self):
        captured = {}

        def fake_start(feature_name=None, save_as_baseline=False):
            captured["feature"] = feature_name
            captured["save_as_baseline"] = save_as_baseline
            return {"status": "running", "run_id": "bench_test", "feature": feature_name}

        self._patch_service("start_benchmark_run_async", fake_start)
        response = self.client.post(
            "/api/bench/run",
            json={"feature": "feature-x", "save_as_baseline": True},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["run_id"], "bench_test")
        self.assertEqual(captured["feature"], "feature-x")
        self.assertTrue(captured["save_as_baseline"])

    def test_run_bench_defaults_without_body(self):
        captured = {}

        def fake_start(feature_name=None, save_as_baseline=False):
            captured["feature"] = feature_name
            return {"status": "running", "run_id": "bench_test"}

        self._patch_service("start_benchmark_run_async", fake_start)
        response = self.client.post("/api/bench/run")
        self.assertEqual(response.status_code, 202)
        self.assertIsNone(captured["feature"])

    def test_run_bench_conflict_returns_409(self):
        def busy_start(feature_name=None, save_as_baseline=False):
            raise RuntimeError("Ya hay una corrida de benchmark en ejecución.")

        self._patch_service("start_benchmark_run_async", busy_start)
        response = self.client.post("/api/bench/run", json={"feature": "x"})
        self.assertEqual(response.status_code, 409)
        self.assertIn("corrida", response.get_json()["error"])

    def test_run_bench_rejects_non_string_feature(self):
        def unexpected(*args, **kwargs):
            raise AssertionError("No debe iniciarse una corrida con body inválido.")

        self._patch_service("start_benchmark_run_async", unexpected)
        response = self.client.post("/api/bench/run", json={"feature": 123})
        self.assertEqual(response.status_code, 400)
        self.assertIn("feature", response.get_json()["error"])

    def test_run_bench_rejects_non_object_body(self):
        def unexpected(*args, **kwargs):
            raise AssertionError("No debe iniciarse una corrida con body inválido.")

        self._patch_service("start_benchmark_run_async", unexpected)
        response = self.client.post("/api/bench/run", json=[1, 2, 3])
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
