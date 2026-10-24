"""GitHub webhook pipeline: análisis de pull requests sobre archivos modificados.

Valida la firma HMAC-SHA256 del webhook con comparación en tiempo constante,
salta SHAs ya analizados (índice persistido en storage/webhook_analyses.json),
descarga el árbol del PR con el clon endurecido (solo https,
protocol.file.allow=never, límites de tamaño y tiempo), obtiene los archivos
modificados con git diff contra la rama base, filtra los hallazgos a esos
archivos y publica comentario y check run en GitHub si hay token.

El código analizado es dato, nunca instrucciones: no se ejecuta. Los valores
de secretos jamás se incluyen en hallazgos ni comentarios.
"""

import fnmatch
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import analyzer

ROOT = Path(__file__).resolve().parent
WEBHOOK_INDEX_FILE = ROOT / "storage" / "webhook_analyses.json"
PR_STATE_FILE = ROOT / "storage" / "webhook_pr_state.json"
GITHUB_API_ROOT = "https://api.github.com"
MAX_INDEX_ENTRIES = 500
MAX_DIFF_FILES = 2000
GITHUB_API_TIMEOUT = 20
COMMENT_MARKER = "<!-- security-control-center-analysis -->"
REPORT_BASE_URL_ENV = "REPORT_BASE_URL"
SECAI_IGNORE_FILE = ".secai-ignore.yml"
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

_sha_lock = threading.Lock()
_pr_state_lock = threading.Lock()
_SAFE_REF = re.compile(r"^[A-Za-z0-9._\-/]{1,200}$")


# ---------------------------------------------------------------------------
# Firma HMAC-SHA256
# ---------------------------------------------------------------------------

def verify_signature(secret: str, signature_header: Optional[str], raw_body: bytes) -> bool:
    """HMAC-SHA256 del cuerpo crudo contra X-Hub-Signature-256, en tiempo constante."""
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# Payload del evento pull_request
# ---------------------------------------------------------------------------

def extract_pr_payload(payload: Any) -> Optional[Dict[str, Any]]:
    """Extrae y valida los campos del evento pull_request que usa el pipeline.
    Devuelve None si el payload está incompleto."""
    if not isinstance(payload, dict):
        return None
    pr = payload.get("pull_request") or {}
    repository = payload.get("repository") or {}
    number = pr.get("number")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_sha = str(head.get("sha") or "")
    head_ref = str(head.get("ref") or "")[:200]
    base_ref = str(base.get("ref") or "")
    full_name = str(repository.get("full_name") or "")
    clone_url = str(repository.get("clone_url") or "")
    if not number or not head_sha or not full_name:
        return None
    if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+(?:\.git)?", clone_url):
        clone_url = f"https://github.com/{full_name}.git"
    return {
        "number": int(number),
        "head_sha": head_sha,
        "head_ref": head_ref,
        "base_ref": base_ref if _SAFE_REF.match(base_ref) and not base_ref.startswith("-") else "",
        "full_name": full_name,
        "clone_url": clone_url,
    }


# ---------------------------------------------------------------------------
# Índice de SHAs ya analizados (persistido, con claim atómico)
# ---------------------------------------------------------------------------

def _sha_key(full_name: str, sha: str) -> str:
    return f"{full_name.lower()}@{sha}"


def load_sha_index() -> Dict[str, Any]:
    try:
        with open(WEBHOOK_INDEX_FILE, "r", encoding="utf-8") as handle:
            data = json.loads(handle.read())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_sha_index(index: Dict[str, Any]) -> None:
    WEBHOOK_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    WEBHOOK_INDEX_FILE.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")


def sha_already_analyzed(full_name: str, sha: str) -> Optional[Dict[str, Any]]:
    with _sha_lock:
        return load_sha_index().get(_sha_key(full_name, sha))


def claim_sha(full_name: str, sha: str, info: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Reserva atómicamente el SHA para análisis. Devuelve (claimed, existing):
    si el SHA ya fue analizado o está en curso, claimed=False y devuelve su registro."""
    with _sha_lock:
        index = load_sha_index()
        existing = index.get(_sha_key(full_name, sha))
        if existing:
            return False, existing
        index[_sha_key(full_name, sha)] = info
        entries = sorted(index.items(),
                         key=lambda item: str((item[1] or {}).get("timestamp", "")),
                         reverse=True)
        _save_sha_index(dict(entries[:MAX_INDEX_ENTRIES]))
        return True, None


def update_sha_entry(full_name: str, sha: str, changes: Dict[str, Any]) -> None:
    with _sha_lock:
        index = load_sha_index()
        key = _sha_key(full_name, sha)
        if key in index and isinstance(index[key], dict):
            index[key].update(changes)
            _save_sha_index(index)


# ---------------------------------------------------------------------------
# Checkout del PR y archivos modificados
# ---------------------------------------------------------------------------

def _git(args: List[str], cwd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "protocol.file.allow=never"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def prepare_pr_checkout(pr: Dict[str, Any], temp_dir: str) -> Tuple[str, List[str], str]:
    """Descarga el árbol del PR (refs/pull/N/head) con fetch superficial endurecido
    y calcula los archivos modificados contra la rama base con git diff.
    Devuelve (head_sha, modified_files, source) con source: "git-diff" | "unavailable".
    Lanza RuntimeError si el head del PR no puede descargarse."""
    url = analyzer._validate_https_url(pr["clone_url"])  # solo https
    init = _git(["init", "-q"], temp_dir)
    if init.returncode != 0:
        raise RuntimeError(f"No se pudo preparar el checkout del PR: {init.stderr.strip()[:200]}")
    remote = _git(["remote", "add", "origin", url], temp_dir)
    if remote.returncode != 0:
        raise RuntimeError(f"No se pudo configurar el remoto del PR: {remote.stderr.strip()[:200]}")
    fetch_head = _git(["fetch", "--depth", "1", "--no-tags", "origin", f"pull/{pr['number']}/head"], temp_dir)
    if fetch_head.returncode != 0:
        detail = (fetch_head.stderr or "").strip()[:200]
        raise RuntimeError(f"No se pudo descargar el head del PR: {detail}")
    checkout = _git(["checkout", "-q", "FETCH_HEAD"], temp_dir)
    if checkout.returncode != 0:
        raise RuntimeError("No se pudo posicionar el árbol del PR.")
    head_sha = _git(["rev-parse", "HEAD"], temp_dir).stdout.strip()
    if not head_sha:
        raise RuntimeError("No se pudo determinar el SHA del PR.")

    base_ref = pr.get("base_ref") or ""
    if base_ref:
        fetch_base = _git(["fetch", "--depth", "1", "--no-tags", "origin", f"refs/heads/{base_ref}"], temp_dir)
        if fetch_base.returncode == 0:
            base_sha = _git(["rev-parse", "FETCH_HEAD"], temp_dir).stdout.strip()
            if base_sha:
                diff = _git(["diff", "--name-only", base_sha, head_sha], temp_dir)
                if diff.returncode == 0:
                    modified = [name.strip() for name in (diff.stdout or "").splitlines() if name.strip()]
                    return head_sha, modified[:MAX_DIFF_FILES], "git-diff"
    return head_sha, [], "unavailable"


# ---------------------------------------------------------------------------
# Filtrado de hallazgos a los archivos modificados
# ---------------------------------------------------------------------------

def recompute_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"total": len(findings)}
    for level in ("critical", "high", "medium", "low"):
        summary[level] = sum(1 for finding in findings if finding.get("severity") == level)
    return summary


def filter_findings_to_files(result: Dict[str, Any], modified_files: List[str]) -> None:
    """Conserva solo los hallazgos cuyo archivo figura entre los modificados
    y recalcula el resumen y los ids."""
    allowed = {name.lower() for name in modified_files}
    findings = [finding for finding in result.get("findings", [])
                if str(finding.get("file", "")).lower() in allowed]
    for index, finding in enumerate(findings, start=1):
        finding["id"] = index
    result["findings"] = findings
    result["summary"] = recompute_summary(findings)


# ---------------------------------------------------------------------------
# Rutas ignoradas por repositorio (.secai-ignore.yml)
# ---------------------------------------------------------------------------

def load_secai_ignore_patterns(repo_dir: str) -> List[str]:
    """Lee .secai-ignore.yml de la raíz del repositorio analizado. Acepta una
    lista directa o un mapping con clave 'ignore'. Archivo ausente o inválido
    → sin patrones (nunca rompe el análisis)."""
    path = Path(repo_dir) / SECAI_IGNORE_FILE
    if not path.is_file():
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get("ignore")
    if not isinstance(data, list):
        return []
    return [str(pattern).strip() for pattern in data if str(pattern).strip()][:100]


def path_is_ignored(file_path: Any, patterns: List[str]) -> bool:
    normalized = str(file_path or "").replace("\\", "/").lstrip("./")
    if not normalized:
        return False
    for pattern in patterns:
        clean = pattern.strip().lstrip("./")
        if not clean:
            continue
        if (fnmatch.fnmatch(normalized, clean)
                or normalized == clean
                or normalized.startswith(clean.rstrip("/") + "/")):
            return True
    return False


def filter_ignored_findings(result: Dict[str, Any], patterns: List[str]) -> int:
    """Quita los hallazgos cuya ruta matchea .secai-ignore.yml. Devuelve cuántos
    se removieron; recalcula resumen e ids."""
    if not patterns:
        return 0
    before = len(result.get("findings", []))
    result["findings"] = [finding for finding in result.get("findings", [])
                          if not path_is_ignored(finding.get("file"), patterns)]
    removed = before - len(result.get("findings", []))
    for index, finding in enumerate(result.get("findings", []), start=1):
        finding["id"] = index
    result["summary"] = recompute_summary(result.get("findings", []))
    return removed


# ---------------------------------------------------------------------------
# Publicación: comentario + check run
# ---------------------------------------------------------------------------

def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _github_api_post(path: str, token: str, body: Dict[str, Any]) -> None:
    request = urllib.request.Request(
        GITHUB_API_ROOT + path,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "security-control-center",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=GITHUB_API_TIMEOUT) as response:
        response.read(1024)


def _github_api_get(path: str, token: str) -> Any:
    request = urllib.request.Request(
        GITHUB_API_ROOT + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "security-control-center",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=GITHUB_API_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace") or "null")


def _github_api_patch(path: str, token: str, body: Dict[str, Any]) -> None:
    request = urllib.request.Request(
        GITHUB_API_ROOT + path,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "security-control-center",
        },
        method="PATCH",
    )
    with urllib.request.urlopen(request, timeout=GITHUB_API_TIMEOUT) as response:
        response.read(1024)


# ---------------------------------------------------------------------------
# Hallazgos nuevos vs corrida anterior (fingerprints persistidos por PR)
# ---------------------------------------------------------------------------

def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Huella estable de un hallazgo (regla + archivo + línea) para comparar
    corridas del mismo PR."""
    raw = f"{finding.get('rule', '')}|{finding.get('file', '')}|{finding.get('line') or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _pr_state_key(full_name: str, number: int) -> str:
    return f"{full_name.lower()}#{number}"


def load_previous_fingerprints(full_name: str, number: int) -> set:
    with _pr_state_lock:
        try:
            with open(PR_STATE_FILE, "r", encoding="utf-8") as handle:
                state = json.loads(handle.read())
        except (OSError, json.JSONDecodeError):
            return set()
        entry = state.get(_pr_state_key(full_name, number)) if isinstance(state, dict) else None
        if not isinstance(entry, dict):
            return set()
        fingerprints = entry.get("fingerprints")
        return set(fingerprints) if isinstance(fingerprints, list) else set()


def save_current_fingerprints(full_name: str, number: int, sha: str,
                              findings: List[Dict[str, Any]]) -> None:
    """Persiste las huellas de la corrida actual para detectar hallazgos nuevos
    en la próxima. Tope de 500 PRs por antigüedad."""
    with _pr_state_lock:
        try:
            with open(PR_STATE_FILE, "r", encoding="utf-8") as handle:
                state = json.loads(handle.read())
            if not isinstance(state, dict):
                state = {}
        except (OSError, json.JSONDecodeError):
            state = {}
        state[_pr_state_key(full_name, number)] = {
            "sha": sha,
            "fingerprints": sorted({finding_fingerprint(f) for f in findings}),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        entries = sorted(state.items(),
                         key=lambda item: str((item[1] or {}).get("timestamp", "")),
                         reverse=True)
        PR_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        PR_STATE_FILE.write_text(json.dumps(dict(entries[:500]), ensure_ascii=False, indent=2),
                                 encoding="utf-8")


def split_new_findings(findings: List[Dict[str, Any]],
                       previous_fingerprints: set) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Separa hallazgos nuevos (no vistos en la corrida anterior del PR) de los ya conocidos."""
    new: List[Dict[str, Any]] = []
    known: List[Dict[str, Any]] = []
    for finding in findings:
        (new if finding_fingerprint(finding) not in previous_fingerprints else known).append(finding)
    return new, known


# ---------------------------------------------------------------------------
# Comentario del PR: resumen en una línea + hallazgos nuevos + reporte
# ---------------------------------------------------------------------------

def _findings_table(findings: List[Dict[str, Any]], limit: int = 20) -> str:
    if not findings:
        return ""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = []
    for finding in sorted(findings, key=lambda item: order.get(item.get("severity"), 4))[:limit]:
        location = f"`{finding.get('file', '?')}:{finding.get('line') or '?'}`"
        tools = ", ".join(finding.get("tools", []))
        rows.append(
            f"| {finding.get('severity')} | {finding.get('rule')} | "
            f"{finding.get('title')} | {location} | {tools} |"
        )
    body = ("\n| Severidad | Regla | Hallazgo | Ubicación | Herramientas |\n"
            "| --- | --- | --- | --- | --- |\n" + "\n".join(rows) + "\n")
    if len(findings) > limit:
        body += f"\n_…y {len(findings) - limit} hallazgo(s) más (reporte completo en la plataforma)._\n"
    return body


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "critical": sum(1 for finding in findings if finding.get("severity") == "critical"),
        "high": sum(1 for finding in findings if finding.get("severity") == "high"),
        "medium": sum(1 for finding in findings if finding.get("severity") == "medium"),
        "low": sum(1 for finding in findings if finding.get("severity") == "low"),
    }


def comment_markdown(pr: Dict[str, Any], findings: List[Dict[str, Any]],
                     new_findings: Optional[List[Dict[str, Any]]] = None,
                     report_url: str = "") -> str:
    """Comentario del PR: marcador para actualización, resumen en una línea,
    hallazgos nuevos por severidad, conocidos plegados y enlace al reporte.
    Nunca incluye código ni valores de secretos."""
    new_findings = findings if new_findings is None else new_findings
    counts = _severity_counts(findings)
    summary_bits = (f"{counts['critical']} críticos, {counts['high']} altos, "
                    f"{counts['medium']} medios, {counts['low']} bajos") if findings else "sin hallazgos"
    summary_line = (
        f"**Resumen:** {len(findings)} hallazgo(s) en archivos modificados "
        f"({summary_bits}) — **{len(new_findings)} nuevo(s)** desde la corrida anterior — "
        f"SHA `{pr['head_sha'][:12]}`"
    )
    if report_url:
        summary_line += f" — [Reporte completo]({report_url})"

    sections: List[str] = [
        COMMENT_MARKER,
        f"### 🛡️ Análisis SAST del PR #{pr['number']}",
        "",
        summary_line,
        "",
    ]

    if not findings:
        sections.append("✅ Sin hallazgos de seguridad en los archivos modificados.")
        return "\n".join(sections)

    new_by_severity = {
        level: [finding for finding in new_findings if finding.get("severity") == level]
        for level in ("critical", "high", "medium", "low")
    }
    if new_findings:
        sections.append("#### 🆕 Hallazgos nuevos (por severidad)")
        sections.append("")
        for level in ("critical", "high", "medium", "low"):
            for finding in new_by_severity[level]:
                tools = ", ".join(finding.get("tools", []))
                sections.append(
                    f"- **{level}** — `{finding.get('rule')}` — {finding.get('title')} — "
                    f"`{finding.get('file', '?')}:{finding.get('line') or '?'}`"
                    + (f" ({tools})" if tools else "")
                )
    known_count = len(findings) - len(new_findings)
    if known_count > 0:
        sections.append("")
        sections.append(f"<details><summary>📋 Hallazgos ya conocidos de corridas anteriores ({known_count})</summary>")
        sections.append(_findings_table([f for f in findings if f not in new_findings]))
        sections.append("</details>")
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Check run: explica por qué pasó o falló (umbral configurable)
# ---------------------------------------------------------------------------

def build_check_output(findings: List[Dict[str, Any]],
                       new_findings: Optional[List[Dict[str, Any]]] = None,
                       fail_severity: Optional[str] = None,
                       only_new: Optional[bool] = None) -> Dict[str, str]:
    """Título, conclusión y explicación del check run.

    Umbral configurable por entorno: CHECK_FAIL_SEVERITY (default "critical") define
    la severidad mínima que bloquea, y CHECK_FAIL_ONLY_NEW (default true) limita la
    evaluación a los hallazgos NUEVOS del PR. Por defecto el check falla solo con
    hallazgos críticos nuevos. Con new_findings=None se evalúan todos los hallazgos.
    """
    fail_severity = (fail_severity or os.environ.get("CHECK_FAIL_SEVERITY", "critical")).lower()
    if only_new is None:
        only_new = os.environ.get("CHECK_FAIL_ONLY_NEW", "true").strip().lower() in ("1", "true", "yes")
    if new_findings is None:
        evaluated = findings
        evaluated_desc = "todos los hallazgos del PR"
    elif only_new:
        evaluated = new_findings
        evaluated_desc = f"solo los hallazgos NUEVOS del PR"
    else:
        evaluated = findings
        evaluated_desc = "todos los hallazgos del PR"
    threshold_rank = _SEVERITY_RANK.get(fail_severity, _SEVERITY_RANK["critical"])
    blocking = [finding for finding in evaluated
                if _SEVERITY_RANK.get(str(finding.get("severity")), 1) >= threshold_rank]
    blocking_count = len(blocking)
    counts = _severity_counts(findings)

    if blocking_count:
        conclusion = "failure"
        title = f"❌ SAST falló: {blocking_count} hallazgo(s) bloqueante(s) (umbral: {fail_severity})"
        summary = (
            f"El check falló porque, con el umbral configurado (severidad mínima que bloquea: "
            f"{fail_severity}, evaluando {evaluated_desc}), se detectaron {blocking_count} hallazgo(s) "
            f"de severidad igual o superior al umbral en los archivos modificados. "
            f"Estos hallazgos bloquean el merge según la política del proyecto; revisá el comentario "
            f"del PR para el detalle y corregí o justificá cada uno."
        )
    elif findings:
        conclusion = "neutral"
        title = f"⚠️ SAST con observaciones: {len(findings)} hallazgo(s) bajo el umbral ({fail_severity})"
        summary = (
            f"El check no falla porque, evaluando {evaluated_desc}, ningún hallazgo alcanza el umbral "
            f"de severidad configurado ({fail_severity}); se tratan como observaciones y se recomienda "
            f"revisarlos antes del merge."
        )
    else:
        conclusion = "success"
        title = "✅ SAST pasó: sin hallazgos"
        summary = (
            "El análisis no encontró hallazgos de seguridad en los archivos modificados del PR, "
            "por lo que el check pasa sin observaciones."
        )
    summary += (f" Desglose: {counts['critical']} crítico(s), {counts['high']} alto(s), "
                f"{counts['medium']} medio(s), {counts['low']} bajo(s).")
    return {"conclusion": conclusion, "title": title, "summary": summary}


def find_existing_comment(pr: Dict[str, Any], token: str) -> Optional[int]:
    """Busca el comentario previo de la plataforma en el PR (por marcador) para
    editarlo en lugar de duplicarlo. None si no existe o la API falla."""
    try:
        comments = _github_api_get(
            f"/repos/{pr['full_name']}/issues/{pr['number']}/comments?per_page=100", token)
    except Exception:
        return None
    if not isinstance(comments, list):
        return None
    for comment in reversed(comments):
        if isinstance(comment, dict) and COMMENT_MARKER in str(comment.get("body", "")):
            comment_id = comment.get("id")
            return int(comment_id) if comment_id else None
    return None


# ---------------------------------------------------------------------------
# Publicación: comentario (create o update) + check run
# ---------------------------------------------------------------------------

def publish_pr_outputs(pr: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, str]:
    """Publica o actualiza el comentario del PR y publica el check run.
    Sin GITHUB_TOKEN ambos quedan en 'skipped'; un fallo de la API queda en
    'error' sin romper nada. Devuelve además el desglose nuevo/conocido."""
    outcomes = {"comment": "skipped", "check": "skipped", "new_findings": 0}
    token = _github_token()
    if not token:
        return outcomes
    findings = result.get("findings") or []
    previous = load_previous_fingerprints(pr["full_name"], pr["number"])
    new_findings, _known = split_new_findings(findings, previous)
    outcomes["new_findings"] = len(new_findings)

    report_url = ""
    base_url = os.environ.get(REPORT_BASE_URL_ENV, "").rstrip("/")
    analysis_id = str(result.get("analysis_id") or "")
    if base_url and analysis_id:
        report_url = f"{base_url}/api/analysis/{analysis_id}"

    markdown = comment_markdown(pr, findings, new_findings, report_url)
    try:
        comment_id = find_existing_comment(pr, token)
        if comment_id:
            _github_api_patch(f"/repos/{pr['full_name']}/issues/comments/{comment_id}",
                              token, {"body": markdown})
            outcomes["comment"] = "updated"
        else:
            _github_api_post(f"/repos/{pr['full_name']}/issues/{pr['number']}/comments",
                             token, {"body": markdown})
            outcomes["comment"] = "published"
    except Exception:
        outcomes["comment"] = "error"

    try:
        output = build_check_output(findings, new_findings=new_findings)
        _github_api_post(f"/repos/{pr['full_name']}/check-runs", token, {
            "name": "sast-security-analysis",
            "head_sha": pr["head_sha"],
            "status": "completed",
            "conclusion": output["conclusion"],
            "output": {"title": output["title"], "summary": output["summary"]},
        })
        outcomes["check"] = "published"
    except Exception:
        outcomes["check"] = "error"

    # La corrida queda registrada para detectar hallazgos NUEVOS en la próxima
    # (solo cuando hay token: sin publicación no hay comparación de nuevos).
    try:
        save_current_fingerprints(pr["full_name"], pr["number"],
                                  str(pr.get("head_sha") or ""), findings)
    except Exception:
        pass
    return outcomes


# ---------------------------------------------------------------------------
# Pipeline del webhook
# ---------------------------------------------------------------------------

def run_pr_analysis(pr: Dict[str, Any], analysis_id: str,
                    progress_callback: Optional[Any] = None) -> Dict[str, Any]:
    """Pipeline completo: checkout del PR, análisis con el motor, filtro por
    archivos modificados y publicación. Lanza RuntimeError en fallos duros."""
    temp_dir = tempfile.mkdtemp(prefix="security-pr-")
    try:
        head_sha, modified_files, files_source = prepare_pr_checkout(pr, temp_dir)

        max_bytes = analyzer._max_repo_bytes()
        size_bytes = analyzer._tree_size_bytes(Path(temp_dir))
        if size_bytes > max_bytes:
            raise RuntimeError(
                f"El árbol del PR excede el límite de {max_bytes // (1024 * 1024)} MB "
                f"(medido {size_bytes // (1024 * 1024)} MB)."
            )

        result = analyzer.analyze_directory(
            temp_dir,
            progress_callback=progress_callback,
            repo_url=f"{pr['clone_url']}#pull/{pr['number']}",
            enable_ai=False,
        )
        if modified_files:
            filter_findings_to_files(result, modified_files)
        ignore_patterns = load_secai_ignore_patterns(temp_dir)
        ignored_removed = filter_ignored_findings(result, ignore_patterns)
        repository = result.setdefault("repository", {})
        repository["commit"] = head_sha
        if pr.get("head_ref"):
            repository["branch"] = pr["head_ref"]
        result["pull_request"] = {
            "number": pr["number"],
            "head_sha": head_sha,
            "base_ref": pr.get("base_ref", ""),
            "modified_files": modified_files,
            "modified_files_source": files_source,
            "secai_ignore": {
                "file": SECAI_IGNORE_FILE,
                "present": bool(ignore_patterns),
                "patterns": len(ignore_patterns),
                "removed_findings": ignored_removed,
            },
        }
        # El id va antes de publicar: el comentario enlaza al reporte de este análisis.
        result["analysis_id"] = analysis_id
        result["github_publishing"] = publish_pr_outputs(pr, result)
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _save_analysis(analysis_id: str, value: Dict[str, Any]) -> None:
    target = ROOT / "storage" / "analyses" / f"{analysis_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def run_pr_analysis_task(pr: Dict[str, Any], analysis_id: str,
                         progress_callback: Optional[Any] = None) -> None:
    """Entrada para la cola del API: corre el pipeline, persiste el resultado en
    storage/analyses/ y actualiza el índice de SHAs. Nunca deja el job colgando."""
    try:
        result = run_pr_analysis(pr, analysis_id, progress_callback)
        _save_analysis(analysis_id, result)
        update_sha_entry(pr["full_name"], pr["head_sha"], {
            "status": "completed",
            "findings": (result.get("summary") or {}).get("total", 0),
        })
    except Exception as exc:
        error = {
            "analysis_id": analysis_id,
            "status": "error",
            "stage": "failed",
            "progress": 100,
            "message": "Analysis failed",
            "error_message": str(exc),
            "repository": {"url": pr.get("clone_url", "")},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_analysis(analysis_id, error)
        update_sha_entry(pr["full_name"], pr["head_sha"], {"status": "error"})
