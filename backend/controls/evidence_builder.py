"""Paquete de evidencia determinista para la revisión por control.

Nada de modelos acá: localiza los archivos de "dónde buscar" de la
especificación, extrae fragmentos acotados (ventana alrededor de las líneas
que matchean las `fragmentos_regex` de la spec) y enumera endpoints, rutas y
recursos. Todo se recorta a un tope de tokens aproximado (chars/4).
"""

import fnmatch
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

CHARS_PER_TOKEN = 4
DEFAULT_MAX_TOKENS = 6000
MAX_FILES_PER_CONTROL = 8
MAX_MATCHES_PER_FILE = 6
CONTEXT_LINES = 12
HEADER_LINES = 30
MAX_FILE_BYTES = 400_000
IGNORED_DIRS = {".git", "node_modules", "storage", ".venv", "venv", "__pycache__",
                "dist", "build", ".next", "coverage", ".semgreplogs"}

# Enumeración determinista de endpoints/rutas por framework.
# Cada entrada: (regex, índice de grupo del método o None, índice de grupo de la ruta o None, lenguaje).
_ENDPOINT_PATTERNS: Tuple[Tuple[Pattern[str], Optional[int], Optional[int], str], ...] = (
    (re.compile(r"@app\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']"), 0, 1, "python"),
    (re.compile(r"@(?:app|router|bp|blueprint|api)\.route\(\s*[\"']([^\"']+)[\"']"), None, 0, "python"),
    (re.compile(r"@(?:router|bp|blueprint|api)\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']"), 0, 1, "python"),
    (re.compile(r"@api_view\(\s*\[\s*[\"'](\w+)"), 0, None, "python"),
    (re.compile(r"\b(?:path|re_path)\(\s*[r]?[\"']([^\"']+)[\"']"), None, 0, "python"),
    (re.compile(r"\.(get|post|put|delete|patch|all)\(\s*[\"']([^\"']+)[\"']"), 0, 1, "javascript"),
    (re.compile(r"@(Get|Post|Put|Delete|Patch)\(\s*[\"']([^\"']+)[\"']"), 0, 1, "typescript"),
)
_CODE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx")


def _iter_repo_files(root: Path) -> List[Path]:
    files: List[Path] = []
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        files.append(path)
        if len(files) > 5000:
            break
    return files


def _find_control_files(control_spec: Dict[str, Any], root: Path) -> List[Path]:
    """Localiza los archivos de 'dónde buscar' con los globs de la especificación."""
    root = Path(root)
    matches: List[Path] = []
    seen = set()
    for pattern in control_spec.get("donde_buscar") or []:
        normalized = pattern.lstrip("./")
        for path in _iter_repo_files(root):
            relative = path.relative_to(root).as_posix()
            if fnmatch.fnmatch(relative, normalized) and relative not in seen:
                seen.add(relative)
                matches.append(path)
            if len(matches) >= MAX_FILES_PER_CONTROL * 4:
                break
        if len(matches) >= MAX_FILES_PER_CONTROL * 4:
            break
    # Prioridad determinista: primero archivos con coincidencias de fragmentos_regex,
    # luego por ruta alfabética; se recorta al máximo de archivos por control.
    return sorted(matches, key=lambda p: p.relative_to(root).as_posix())[:MAX_FILES_PER_CONTROL]


def _read_lines(path: Path) -> List[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _fragment_windows(lines: List[str], regexes: List[Pattern[str]]) -> List[Tuple[int, int]]:
    """Ventanas [inicio, fin] (1-indexed, inclusivas) alrededor de las líneas que matchean."""
    hit_lines = set()
    for index, text in enumerate(lines, start=1):
        for regex in regexes:
            if regex.search(text):
                hit_lines.add(index)
                break
        if len(hit_lines) >= MAX_MATCHES_PER_FILE:
            break
    windows = []
    for hit in sorted(hit_lines):
        start = max(1, hit - CONTEXT_LINES)
        end = min(len(lines), hit + CONTEXT_LINES)
        if windows and start <= windows[-1][1] + 1:
            windows[-1] = (windows[-1][0], max(windows[-1][1], end))
        else:
            windows.append((start, end))
    if not windows:
        windows = [(1, min(HEADER_LINES, len(lines)))]
    return windows


def _package_file(path: Path, root: Path, regexes: List[Pattern[str]]) -> Optional[Dict[str, Any]]:
    lines = _read_lines(path)
    if not lines:
        return None
    fragments = []
    for start, end in _fragment_windows(lines, regexes):
        fragments.append({
            "linea_inicio": start,
            "linea_fin": end,
            "lineas": [{"linea": n, "text": lines[n - 1]} for n in range(start, end + 1)],
        })
    if not fragments:
        return None
    return {
        "archivo": path.relative_to(root).as_posix(),
        "total_lineas": len(lines),
        "fragmentos": fragments,
    }


def estimate_tokens(package: Dict[str, Any]) -> int:
    total_chars = 0
    for file_entry in package.get("archivos", []):
        for fragment in file_entry.get("fragmentos", []):
            total_chars += sum(len(line["text"]) for line in fragment.get("lineas", []))
    return total_chars // CHARS_PER_TOKEN


def _trim_to_token_cap(package: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
    """Recorta fragmentos (del final hacia adelante) hasta quedar bajo el tope."""
    removed_any = False
    while estimate_tokens(package) > max_tokens:
        removed = False
        for file_entry in reversed(package.get("archivos", [])):
            if file_entry.get("fragmentos"):
                file_entry["fragmentos"].pop()
                removed = True
                removed_any = True
                break
        if not removed:
            break
    package["archivos"] = [entry for entry in package["archivos"] if entry.get("fragmentos")]
    package["truncado"] = bool(removed_any) or estimate_tokens(package) >= max_tokens
    return package


def build_package(control_spec: Dict[str, Any], root: Path,
                  max_tokens: Optional[int] = None) -> Dict[str, Any]:
    """Construye el paquete de evidencia de un control (determinista)."""
    root = Path(root)
    cap = int(max_tokens or DEFAULT_MAX_TOKENS)
    regexes = [re.compile(r) for r in control_spec.get("fragmentos_regex") or []]
    files = []
    for path in _find_control_files(control_spec, root):
        packaged = _package_file(path, root, regexes)
        if packaged:
            files.append(packaged)
    package = {
        "control_id": control_spec["id"],
        "stack": detect_stack_labels(root),
        "archivos": files,
        "endpoints": enumerate_endpoints(root),
        "truncado": False,
    }
    return _trim_to_token_cap(package, cap)


def build_endpoint_package(control_spec: Dict[str, Any], root: Path,
                           endpoint: Dict[str, Any],
                           max_tokens: Optional[int] = None) -> Dict[str, Any]:
    """Paquete para juzgar UN endpoint (RBAC/IDOR): ventana centrada en su declaración."""
    root = Path(root)
    cap = int(max_tokens or DEFAULT_MAX_TOKENS)
    path = root / endpoint["archivo"]
    lines = _read_lines(path)
    if not lines:
        return {"control_id": control_spec["id"], "endpoint": endpoint, "archivos": [],
                "endpoints": [endpoint], "truncado": False}
    start = max(1, int(endpoint["linea"]) - CONTEXT_LINES * 3)
    end = min(len(lines), int(endpoint["linea"]) + CONTEXT_LINES * 3)
    package = {
        "control_id": control_spec["id"],
        "endpoint": endpoint,
        "archivos": [{
            "archivo": endpoint["archivo"],
            "total_lineas": len(lines),
            "fragmentos": [{
                "linea_inicio": start,
                "linea_fin": end,
                "lineas": [{"linea": n, "text": lines[n - 1]} for n in range(start, end + 1)],
            }],
        }],
        "endpoints": [endpoint],
        "truncado": False,
    }
    return _trim_to_token_cap(package, cap)


def enumerate_endpoints(root: Path) -> List[Dict[str, Any]]:
    """Enumera endpoints/rutas de forma determinista (FastAPI, Flask, Django,
    Express/Nest y Next.js route handlers)."""
    root = Path(root)
    endpoints: List[Dict[str, Any]] = []
    for path in _iter_repo_files(root):
        if path.suffix not in _CODE_SUFFIXES:
            continue
        lines = _read_lines(path)
        if not lines:
            continue
        relative = path.relative_to(root).as_posix()
        for number, text in enumerate(lines, start=1):
            for regex, method_index, route_index, language in _ENDPOINT_PATTERNS:
                match = regex.search(text)
                if not match:
                    continue
                groups = match.groups()
                method = ""
                route = ""
                if method_index is not None and len(groups) > method_index:
                    method = groups[method_index].upper()
                if route_index is not None and len(groups) > route_index:
                    route = groups[route_index]
                endpoints.append({
                    "metodo": method,
                    "ruta": route,
                    "archivo": relative,
                    "linea": number,
                    "lenguaje": language,
                })
                break
        if len(endpoints) >= 500:
            break
    return endpoints


def detect_stack_labels(root: Path) -> List[str]:
    """Etiquetas de stack detectadas de forma determinista (sin invocar scanners)."""
    root = Path(root)
    labels: List[str] = []
    checks = (
        ("requirements.txt", "python"), ("pyproject.toml", "python"), ("Pipfile", "python"),
        ("package.json", "node"), ("go.mod", "go"), ("Dockerfile", "docker"),
        ("docker-compose.yml", "docker"),
    )
    for name, label in checks:
        if (root / name).is_file() and label not in labels:
            labels.append(label)
    for path in root.glob("*.tf"):
        if "terraform" not in labels:
            labels.append("terraform")
            break
    if (root / ".github" / "workflows").is_dir() and "github-actions" not in labels:
        labels.append("github-actions")
    return labels


def package_to_text(package: Dict[str, Any]) -> str:
    """Serializa el paquete para el prompt (solo datos, sin instrucciones)."""
    parts = [f"[STACK] {', '.join(package.get('stack') or []) or 'n/d'}"]
    for entry in package.get("archivos", []):
        parts.append(f"[ARCHIVO] {entry['archivo']} ({entry['total_lineas']} líneas)")
        for fragment in entry["fragmentos"]:
            parts.append(f"[LÍNEAS {fragment['linea_inicio']}-{fragment['linea_fin']}]")
            for line in fragment["lineas"]:
                parts.append(f"{line['linea']}: {line['text']}")
    endpoints = package.get("endpoints") or []
    if endpoints:
        parts.append("[ENDPOINTS DETECTADOS]")
        for endpoint in endpoints[:100]:
            method = endpoint.get("metodo") or "RUTA"
            parts.append(f"- {method} {endpoint.get('ruta')} ({endpoint['archivo']}:{endpoint['linea']})")
    return "\n".join(parts)
