"""Pruebas de Cobertura Políglota y Detección de Stack v2 (F14).

Verifica según los criterios de aceptación de HACER.md (4.6):
1. Fixtures para 8+ lenguajes (Python, JS/TS, Java, Go, Ruby, PHP, Rust, C#) con dependencias y código.
2. Detección de volúmenes por lenguaje en archivos y bytes sin ejecutar el repositorio.
3. Detección de monorepos con múltiples subproyectos.
4. Fixture de lenguaje sin soporte SAST dedicado (Elixir) emite 'completed_with_gaps' y recomienda IA.
5. Principio de cobertura declarada: nunca reportar 'limpio' cuando no se pudo analizar.
"""

import os
from pathlib import Path
import pytest

from tools.stack_detector import detect_stack_v2
from tools.coverage import build_coverage_block
from tools.registry import get_tool_registry


@pytest.fixture
def polyglot_repo(tmp_path):
    """Crea una estructura de prueba con múltiples lenguajes y manifiestos."""
    # 1. Python
    py_dir = tmp_path / "backend_py"
    py_dir.mkdir()
    (py_dir / "app.py").write_text("import pickle\ndef load(d): return pickle.loads(d)\n", encoding="utf-8")
    (py_dir / "requirements.txt").write_text("flask==0.12\nrequests==2.19.1\n", encoding="utf-8")

    # 2. JavaScript / TypeScript
    js_dir = tmp_path / "frontend_js"
    js_dir.mkdir()
    (js_dir / "index.ts").write_text("const el = document.getElementById('app');\n", encoding="utf-8")
    (js_dir / "package.json").write_text('{"name": "front", "dependencies": {"axios": "0.18.0"}}\n', encoding="utf-8")
    (js_dir / "package-lock.json").write_text('{"name": "front", "lockfileVersion": 2}\n', encoding="utf-8")

    # 3. Go
    go_dir = tmp_path / "services" / "auth_go"
    go_dir.mkdir(parents=True)
    (go_dir / "main.go").write_text('package main\nfunc main() {}\n', encoding="utf-8")
    (go_dir / "go.mod").write_text('module auth\ngo 1.22\n', encoding="utf-8")

    # 4. Java
    java_dir = tmp_path / "legacy_java"
    java_dir.mkdir()
    (java_dir / "App.java").write_text('public class App { public static void main(String[] args) {} }\n', encoding="utf-8")
    (java_dir / "pom.xml").write_text('<project><modelVersion>4.0.0</modelVersion></project>\n', encoding="utf-8")

    # 5. Ruby
    rb_dir = tmp_path / "ruby_app"
    rb_dir.mkdir()
    (rb_dir / "app.rb").write_text('require "sinatra"\nget "/" do "hello" end\n', encoding="utf-8")
    (rb_dir / "Gemfile").write_text('source "https://rubygems.org"\ngem "rails", "5.2.0"\n', encoding="utf-8")

    # 6. PHP
    php_dir = tmp_path / "web_php"
    php_dir.mkdir()
    (php_dir / "index.php").write_text('<?php echo $_GET["q"]; ?>\n', encoding="utf-8")
    (php_dir / "composer.json").write_text('{"require": {"monolog/monolog": "1.0.*"}}\n', encoding="utf-8")

    # 7. Rust
    rs_dir = tmp_path / "core_rust"
    rs_dir.mkdir()
    (rs_dir / "main.rs").write_text('fn main() { println!("secure"); }\n', encoding="utf-8")
    (rs_dir / "Cargo.toml").write_text('[package]\nname = "core"\nversion = "0.1.0"\n', encoding="utf-8")

    # 8. C# (.NET)
    cs_dir = tmp_path / "dotnet_app"
    cs_dir.mkdir()
    (cs_dir / "Program.cs").write_text('using System;\nclass Program { static void Main() {} }\n', encoding="utf-8")
    (cs_dir / "app.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>\n', encoding="utf-8")

    return tmp_path


def test_detect_stack_v2_polyglot(polyglot_repo):
    """Verifica detección de 8+ lenguajes, volúmenes de archivos y monorepos."""
    stack = detect_stack_v2(str(polyglot_repo))

    # Lenguajes detectados
    langs = stack["languages"]
    for expected in ("python", "typescript", "go", "java", "ruby", "php", "rust", "csharp"):
        assert expected in langs, f"Falta lenguaje {expected} en {langs}"

    # Estadísticas de archivos
    stats = stack["languages_stats"]
    assert stats["python"]["files"] >= 1
    assert stats["python"]["bytes"] > 0
    assert stats["go"]["files"] >= 1
    assert stats["ruby"]["files"] >= 1

    # Detección de subproyectos en monorepo
    subprojects = stack["monorepo_roots"]
    assert len(subprojects) >= 4
    assert any("backend_py" in sp for sp in subprojects)
    assert any("frontend_js" in sp for sp in subprojects)
    assert any("auth_go" in sp for sp in subprojects)


def test_unsupported_language_emits_coverage_gaps(tmp_path):
    """Un lenguaje sin soporte SAST dedicado (ej. Elixir) emite lagunas de cobertura."""
    elixir_dir = tmp_path / "elixir_app"
    elixir_dir.mkdir()
    (elixir_dir / "mix.exs").write_text('defmodule App.MixProject do\nend\n', encoding="utf-8")
    (elixir_dir / "app.ex").write_text('defmodule App do\n  def hello, do: :world\nend\n', encoding="utf-8")

    stack = detect_stack_v2(str(tmp_path))
    assert "elixir" in stack["languages"]

    # Simular estado de herramientas (sin SAST para Elixir)
    tools_status = {"gitleaks": "completed", "osv-scanner": "completed"}
    coverage = build_coverage_block(stack, tools_status, findings=[])

    assert coverage["status"] == "completed_with_gaps"
    assert any("elixir: sin herramienta SAST" in gap for gap in coverage["gaps"])
    assert coverage["ai_review_recommended"] is True


def test_coverage_block_complete_when_all_covered(tmp_path):
    """Cuando los lenguajes presentes cuentan con SAST y SCA activos, el estado es 'completed'."""
    py_dir = tmp_path / "app"
    py_dir.mkdir()
    (py_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (py_dir / "requirements.txt").write_text("flask==2.3.0\n", encoding="utf-8")

    stack = detect_stack_v2(str(tmp_path))
    tools_status = {
        "semgrep": "completed",
        "bandit": "completed",
        "osv-scanner": "completed",
        "gitleaks": "completed",
    }
    coverage = build_coverage_block(stack, tools_status, findings=[])

    assert coverage["status"] == "completed"
    assert len(coverage["gaps"]) == 0
    assert coverage["languages"][0]["name"] == "python"
    assert coverage["languages"][0]["sast"] is not None


def test_tool_registry_inventory():
    """Valida que el registro contenga el catálogo de herramientas y métodos de doctor."""
    reg = get_tool_registry()
    status_list = reg.get_installed_tools_status()
    assert len(status_list) >= 12
    tool_ids = {t["id"] for t in status_list}
    assert "semgrep" in tool_ids
    assert "gitleaks" in tool_ids
    assert "osv-scanner" in tool_ids
    assert "checkov" in tool_ids
