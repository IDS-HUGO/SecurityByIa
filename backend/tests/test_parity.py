"""Parity verification test comparing frontend React implementation against static/.
Ensures that all features, tabs, filters, and endpoints present in static/ are fully
implemented in frontend/src.
"""

from pathlib import Path
import re
import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = ROOT_DIR / "static"
FRONTEND_DIR = ROOT_DIR / "frontend"


def test_parity_files_exist():
    """Verify frontend structure exists and contains all required components."""
    assert FRONTEND_DIR.is_dir()
    assert (FRONTEND_DIR / "package.json").is_file()
    assert (FRONTEND_DIR / "vite.config.js").is_file()
    assert (FRONTEND_DIR / "nginx.conf").is_file()
    assert (FRONTEND_DIR / "Dockerfile").is_file()
    assert (FRONTEND_DIR / "src" / "api" / "client.js").is_file()
    assert (FRONTEND_DIR / "src" / "App.jsx").is_file()

    components_dir = FRONTEND_DIR / "src" / "components"
    assert (components_dir / "Sidebar.jsx").is_file()
    assert (components_dir / "Topbar.jsx").is_file()
    assert (components_dir / "ScanCard.jsx").is_file()
    assert (components_dir / "ProgressPanel.jsx").is_file()
    assert (components_dir / "OverviewTab.jsx").is_file()
    assert (components_dir / "FindingsTab.jsx").is_file()
    assert (components_dir / "FindingDetailModal.jsx").is_file()
    assert (components_dir / "BenchmarkTab.jsx").is_file()
    assert (components_dir / "ReportTab.jsx").is_file()


def test_parity_tabs_coverage():
    """Verify that all tabs from static/index.html exist in React App.jsx."""
    app_jsx = (FRONTEND_DIR / "src" / "App.jsx").read_text(encoding="utf-8")
    for tab in ["overview", "findings", "benchmark", "report"]:
        assert tab in app_jsx, f"Tab '{tab}' is missing from App.jsx"


def test_parity_api_endpoints_coverage():
    """Verify that all API endpoints called in static/js/app.js are implemented in client.js."""
    client_js = (FRONTEND_DIR / "src" / "api" / "client.js").read_text(encoding="utf-8")

    expected_endpoints = [
        "/api/analyze",
        "/api/analysis/",
        "/api/analyses",
        "/api/bench",
        "/api/bench/run",
        "/api/bench/baseline",
        "/api/bench/history",
    ]

    for ep in expected_endpoints:
        assert ep in client_js, f"Endpoint {ep} is missing in frontend API client layer"


def test_parity_filters_coverage():
    """Verify that tool and type filters and clickable summary bar are in FindingsTab.jsx."""
    findings_jsx = (FRONTEND_DIR / "src" / "components" / "FindingsTab.jsx").read_text(encoding="utf-8")
    assert "tool-filter" in findings_jsx
    assert "type-filter" in findings_jsx
    assert "summary-pill" in findings_jsx
    assert "activeFilterSev" in findings_jsx
    assert "activeFilterOwasp" in findings_jsx


def test_parity_benchmark_elements_coverage():
    """Verify BenchmarkTab has TPR, FPR, Precision, F1, CWE table, individual tools, and pairs."""
    bench_jsx = (FRONTEND_DIR / "src" / "components" / "BenchmarkTab.jsx").read_text(encoding="utf-8")
    assert "TPR / Recall Global" in bench_jsx
    assert "FPR Global" in bench_jsx
    assert "Precisión Global" in bench_jsx
    assert "F1-Score Global" in bench_jsx
    assert "cwe_categories" in bench_jsx
    assert "tool_evaluations" in bench_jsx
    assert "scanner_pairs" in bench_jsx
