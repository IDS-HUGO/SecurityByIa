"""Pruebas pytest del clon endurecido en analyzer.analyze_repo.

Cubren: URL inválida (solo https), repositorio demasiado grande (límite de
tamaño), timeout del clon con limpieza garantizada del directorio temporal,
comando de clon endurecido (--no-tags, --single-branch, protocol.file.allow=never,
`--` antes de la URL), registro del SHA exacto y modo de historial completo
(sin --depth 1, con Gitleaks revisando el historial de git).

No requieren red ni git: subprocess.run y el escaneo se sustituyen por stubs.

Ejecución:
    python -m pytest tests/test_analyzer_clone.py -v
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

import analyzer


FAKE_URL = "https://example.com/acme/repo.git"
FAKE_SHA = "abc123def4567890"


class FakeCompleted:
    """CompletedProcess mínimo para los stubs de subprocess.run."""

    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def make_fake_run(commands, payload=b"x = 1\n"):
    """Stub de subprocess.run: simula `git clone` (crea el directorio destino
    con un archivo del tamaño dado y registra el comando) y `git rev-parse`
    (devuelve un SHA fijo)."""

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        if "clone" in cmd:
            call_kwargs.update(kwargs)
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "app.py").write_bytes(payload)
            return FakeCompleted()
        if "rev-parse" in cmd and "--abbrev-ref" in cmd:
            return FakeCompleted(stdout="main\n")
        if "rev-parse" in cmd:
            return FakeCompleted(stdout=FAKE_SHA + "\n")
        raise AssertionError(f"subprocess.run inesperado: {cmd}")

    call_kwargs = {}
    fake_run.call_kwargs = call_kwargs
    return fake_run


def temp_dirs_snapshot():
    return set(Path(tempfile.gettempdir()).glob("security-analysis-*"))


# ---------------------------------------------------------------------------
# URL inválida: solo https, rechazo antes de invocar subprocess
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://example.com/acme/repo.git",
    "git@github.com:acme/repo.git",
    "ssh://git@github.com/acme/repo.git",
    "https://",
    "",
])
def test_invalid_url_rejected_before_any_subprocess(monkeypatch, url):
    def no_subprocess(cmd, **kwargs):
        raise AssertionError(f"No debe invocarse subprocess con URL inválida: {url}")

    monkeypatch.setattr(analyzer.subprocess, "run", no_subprocess)
    with pytest.raises(RuntimeError, match="URL"):
        analyzer.analyze_repo(url)


# ---------------------------------------------------------------------------
# Repositorio demasiado grande: límite de tamaño + limpieza del temporal
# ---------------------------------------------------------------------------

def test_oversized_repo_rejected_and_temp_cleaned(monkeypatch):
    monkeypatch.setenv("SECURITY_MAX_REPO_MB", "1")
    commands = []
    fake_run = make_fake_run(commands, payload=b"A" * (2 * 1024 * 1024))  # 2 MB > 1 MB
    monkeypatch.setattr(analyzer.subprocess, "run", fake_run)
    monkeypatch.setattr(
        analyzer, "analyze_directory",
        lambda *args, **kwargs: {"status": "completed", "repository": {}})

    before = temp_dirs_snapshot()
    with pytest.raises(RuntimeError, match="exceeds"):
        analyzer.analyze_repo(FAKE_URL)
    assert temp_dirs_snapshot() == before, "el directorio temporal debe limpiarse"


# ---------------------------------------------------------------------------
# Timeout del clon: error claro + limpieza garantizada
# ---------------------------------------------------------------------------

def test_clone_timeout_raises_and_cleans_temp(monkeypatch):
    def timeout_run(cmd, **kwargs):
        if "clone" in cmd:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 300))
        raise AssertionError(f"subprocess.run inesperado: {cmd}")

    monkeypatch.setattr(analyzer.subprocess, "run", timeout_run)
    before = temp_dirs_snapshot()
    with pytest.raises(RuntimeError, match="timed out"):
        analyzer.analyze_repo(FAKE_URL)
    assert temp_dirs_snapshot() == before, "el directorio temporal debe limpiarse"


# ---------------------------------------------------------------------------
# Comando de clon endurecido: flags, `--` antes de la URL y timeout del entorno
# ---------------------------------------------------------------------------

def test_clone_command_is_hardened(monkeypatch):
    commands = []
    fake_run = make_fake_run(commands)
    monkeypatch.setenv("SECURITY_CLONE_TIMEOUT", "42")
    monkeypatch.setattr(analyzer.subprocess, "run", fake_run)
    monkeypatch.setattr(
        analyzer, "analyze_directory",
        lambda *args, **kwargs: {"status": "completed", "repository": {}})

    analyzer.analyze_repo(FAKE_URL)

    clone_cmd = next(cmd for cmd in commands if "clone" in cmd)
    assert clone_cmd[0] == "git"
    assert "protocol.file.allow=never" in clone_cmd
    assert "--no-tags" in clone_cmd
    assert "--single-branch" in clone_cmd
    assert "--depth" in clone_cmd  # modo por defecto: shallow
    separator = clone_cmd.index("--")
    assert clone_cmd[separator + 1] == FAKE_URL  # la URL va después de `--`
    assert clone_cmd[-2] == FAKE_URL and clone_cmd[-1] != FAKE_URL
    assert fake_run.call_kwargs.get("timeout") == 42  # límite de tiempo del clon


# ---------------------------------------------------------------------------
# Modo historial completo: sin --depth 1, Gitleaks revisa el historial de git
# ---------------------------------------------------------------------------

def test_full_history_mode(monkeypatch):
    commands = []
    monkeypatch.setattr(analyzer.subprocess, "run", make_fake_run(commands))

    captured = {}

    def fake_scan(target_dir, progress_callback=None, repo_url=None, enable_ai=True,
                  scan_git_history=False, timeout_budget=None):
        captured["scan_git_history"] = scan_git_history
        captured["target_existed"] = Path(target_dir).is_dir()
        return {"status": "completed", "repository": {"url": repo_url, "name": "repo"}}

    monkeypatch.setattr(analyzer, "analyze_directory", fake_scan)

    result = analyzer.analyze_repo(FAKE_URL, full_history=True)

    clone_cmd = next(cmd for cmd in commands if "clone" in cmd)
    assert "--depth" not in clone_cmd, "el historial completo no usa --depth 1"
    assert "--single-branch" in clone_cmd and "--no-tags" in clone_cmd
    assert captured["scan_git_history"] is True, "Gitleaks debe revisar el historial"
    assert captured["target_existed"] is True
    assert result["repository"]["commit"] == FAKE_SHA
    assert result["repository"]["branch"] == "main"


# ---------------------------------------------------------------------------
# SHA exacto registrado en el resultado + limpieza también tras el éxito
# ---------------------------------------------------------------------------

def test_exact_commit_recorded_and_temp_cleaned(monkeypatch):
    commands = []
    monkeypatch.setattr(analyzer.subprocess, "run", make_fake_run(commands))
    monkeypatch.setattr(
        analyzer, "analyze_directory",
        lambda *args, **kwargs: {"status": "completed", "repository": {"url": "x"}})

    before = temp_dirs_snapshot()
    result = analyzer.analyze_repo(FAKE_URL)
    assert result["repository"]["commit"] == FAKE_SHA
    assert result["repository"]["branch"] == "main"
    assert temp_dirs_snapshot() == before, "el temporal se elimina también en éxito"
