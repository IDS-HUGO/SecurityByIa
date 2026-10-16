"""Stack detection and optional security tools for the analysis pipeline.

Detects languages, dependency managers, IaC, containers and CI configuration
in the analyzed repository and runs only the tools that apply. Every runner
returns (findings, status); a missing binary yields status "unavailable" and
never breaks the scan — mirroring how analyzer.py treats Gitleaks. All
adapters emit findings in the exact analyzer.py finding schema, each stamped
with the detecting tool so the pipeline can attach multi-tool attribution
("tools": [...]) and merge repeated detections across tools.

The analyzed repository is only ever read: the scanners parse files, they
never execute the code under analysis.
"""

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

OWASP_OUTDATED = "A06:2021 - Vulnerable and Outdated Components"
OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
OWASP_INJECTION = "A03:2021 - Injection"
OWASP_SECRETS = "A02:2021 - Cryptographic Failures"

_PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "vendor", "dist", "build"}
_MAX_LISTED_FILES = 50
_MAX_YAML_SNIFFED = 200
_MAX_SBOM_PACKAGES = 500
_MAX_LICENSES = 100
_MAX_SCORECARD_CHECKS = 30
_MERGE_LIMIT = 3000

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CWE_OUTDATED = "CWE-1104"
_CWE_CONFIG = "CWE-16"


def _tool_bin(name: str, env_var: str) -> Optional[str]:
    """Locate a scanner binary: env override first, then PATH."""
    custom = os.environ.get(env_var)
    if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
        return custom
    return shutil.which(name)


def _clamp_timeout(default_seconds: int, budget_seconds: Optional[int]) -> int:
    if not budget_seconds:
        return default_seconds
    return max(5, min(default_seconds, int(budget_seconds)))


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path


def _cwe_key(finding: Dict[str, Any]) -> str:
    cwe = finding.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    match = re.search(r"CWE-\d+", str(cwe or ""), re.IGNORECASE)
    return match.group(0).upper() if match else "CWE-OTHER"


def _stamp(finding: Dict[str, Any], tool: str) -> Dict[str, Any]:
    """Mark provenance: per-field sources plus the tool list used for attribution."""
    finding["sources"] = {field: tool for field in finding if field != "sources"}
    finding["tools"] = [tool]
    return finding


def _make_finding(
    tool: str,
    rule: str,
    severity: str,
    file: str,
    line: Optional[int],
    title: str,
    problem: str,
    solution: str,
    cwe: Optional[List[str]] = None,
    owasp: str = OWASP_OUTDATED,
    references: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finding: Dict[str, Any] = {
        "id": 0,
        "rule": rule,
        "owasp": owasp,
        "cwe": list(cwe or []),
        "references": list(references or []),
        "severity": severity if severity in _SEVERITY_RANK else "medium",
        "file": file,
        "line": line,
        "title": title,
        "problem": problem,
        "solution": solution,
        "false_positive": False,
        "status": "open",
        "code_context": [],
    }
    if extra:
        finding.update(extra)
    return _stamp(finding, tool)


# ---------------------------------------------------------------------------
# Stack detection
# ---------------------------------------------------------------------------

def detect_stack(root: str) -> Dict[str, Any]:
    """Detect languages, dependency managers, IaC, containers and CI files.

    Only reads filenames (plus a bounded 2 KB sniff of YAML headers for
    CloudFormation); never parses or executes repository content.
    """
    stack: Dict[str, Any] = {
        "languages": [],
        "dependency_files": [],
        "package_managers": [],
        "requirements_files": [],
        "package_lock": False,
        "terraform": [],
        "cloudformation": [],
        "dockerfiles": [],
        "github_workflows": [],
        "dependabot": False,
    }
    languages = set()
    managers = set()
    dep_files: List[str] = []
    req_files: List[str] = []
    has_python = False
    has_node = False
    yaml_sniffed = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _PRUNE_DIRS)
        rel_dir = _rel(dirpath, root)
        for name in sorted(filenames):
            lower = name.lower()
            rel = f"{rel_dir}/{name}" if rel_dir != "." else name

            if rel.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
                stack["github_workflows"].append(rel)
                continue
            if lower in ("dependabot.yml", "dependabot.yaml") and rel.startswith(".github/"):
                stack["dependabot"] = True
                continue
            if lower.endswith((".tf", ".tfvars")):
                stack["terraform"].append(rel)
                continue
            if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
                stack["dockerfiles"].append(rel)
                continue

            if lower.endswith(".py"):
                has_python = True
            if lower.endswith(".txt") and lower.startswith("requirements"):
                req_files.append(rel)
                dep_files.append(rel)
                has_python = True
                languages.add("python")
                continue
            if lower in ("pyproject.toml", "setup.py", "setup.cfg", "pipfile"):
                has_python = True
                languages.add("python")
                if lower == "pipfile":
                    managers.add("pipenv")
                if lower == "pyproject.toml":
                    dep_files.append(rel)
                continue
            if lower == "poetry.lock":
                has_python = True
                languages.add("python")
                managers.add("poetry")
                dep_files.append(rel)
                continue
            if lower == "package.json":
                has_node = True
                languages.add("node")
                continue
            if lower == "package-lock.json":
                stack["package_lock"] = True
                has_node = True
                languages.add("node")
                managers.add("npm")
                dep_files.append(rel)
                continue
            if lower in ("yarn.lock", "pnpm-lock.yaml"):
                has_node = True
                languages.add("node")
                managers.add("yarn" if lower == "yarn.lock" else "pnpm")
                dep_files.append(rel)
                continue
            if lower == "pom.xml":
                languages.add("java")
                managers.add("maven")
                dep_files.append(rel)
                continue
            if lower in ("build.gradle", "build.gradle.kts"):
                languages.add("java")
                managers.add("gradle")
                dep_files.append(rel)
                continue
            if lower == "go.mod":
                languages.add("go")
                managers.add("go")
                dep_files.append(rel)
                continue
            if lower == "gemfile.lock":
                languages.add("ruby")
                managers.add("bundler")
                dep_files.append(rel)
                continue
            if lower == "cargo.lock":
                languages.add("rust")
                managers.add("cargo")
                dep_files.append(rel)
                continue
            if lower == "composer.lock":
                languages.add("php")
                managers.add("composer")
                dep_files.append(rel)
                continue
            if lower.endswith(".csproj") or lower == "packages.lock.json":
                languages.add("dotnet")
                managers.add("nuget")
                dep_files.append(rel)
                continue

            if (lower.endswith((".yaml", ".yml")) and not rel.startswith(".github/")
                    and yaml_sniffed < _MAX_YAML_SNIFFED):
                yaml_sniffed += 1
                try:
                    with open(os.path.join(dirpath, name), "r", encoding="utf-8", errors="replace") as handle:
                        head = handle.read(2048)
                    if "AWSTemplateFormatVersion" in head:
                        stack["cloudformation"].append(rel)
                except OSError:
                    continue

    stack["has_python"] = has_python
    stack["has_node"] = has_node
    stack["languages"] = sorted(languages)
    stack["package_managers"] = sorted(managers)
    stack["dependency_files"] = dep_files[:_MAX_LISTED_FILES]
    stack["requirements_files"] = req_files[:_MAX_LISTED_FILES]
    for key in ("terraform", "cloudformation", "dockerfiles", "github_workflows"):
        stack[key] = stack[key][:_MAX_LISTED_FILES]
    return stack


# ---------------------------------------------------------------------------
# Shared subprocess helper
# ---------------------------------------------------------------------------

def _run_process(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300) -> Tuple[str, int, str]:
    """Run a scanner and return (stdout, returncode, status).

    status: completed | timeout | unavailable. The caller decides how to
    interpret the return code (most scanners exit 1 when they find issues).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return "", -1, "timeout"
    except OSError:
        return "", -1, "unavailable"
    return result.stdout or "", result.returncode or 0, "completed"


# ---------------------------------------------------------------------------
# OSV-Scanner (vulnerable dependencies)
# ---------------------------------------------------------------------------

def _run_osv(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("osv-scanner", "OSV_SCANNER_PATH")
    if not binary:
        return [], "unavailable"
    stdout, code, status = _run_process([binary, "--format", "json", "-r", root], timeout=timeout)
    if status != "completed" or (code not in (0, 1) and not stdout):
        return [], "error" if status == "completed" else status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    findings: List[Dict[str, Any]] = []
    for source in data.get("results", []) or []:
        source_path = str((source.get("source") or {}).get("path", ""))
        for package_block in source.get("packages", []) or []:
            package = package_block.get("package") or {}
            name = str(package.get("name", "unknown"))
            version = str(package.get("version", "?"))
            ecosystem = str(package.get("ecosystem", ""))
            for vuln in package_block.get("vulnerabilities", []) or []:
                findings.append(
                    _finding_from_osv(vuln, name, version, ecosystem, source_path, root)
                )
    return findings, "completed"


def _parse_cvss_score_from_osv(vuln: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Extract CVSS score and vector/text from OSV vulnerability object."""
    for item in (vuln.get("severity") or []):
        if not isinstance(item, dict):
            continue
        score_val = str(item.get("score") or "").strip()
        if "AV:" in score_val or score_val.startswith("CVSS:"):
            val = 5.0
            if "AV:N" in score_val:
                val += 2.0
            if "AC:L" in score_val:
                val += 0.5
            if "PR:N" in score_val:
                val += 1.0
            if "UI:N" in score_val:
                val += 0.3
            if "C:H" in score_val or "I:H" in score_val or "A:H" in score_val:
                val += 1.2
            return min(10.0, round(val, 1)), score_val

        m_num = re.search(r"(\d+\.\d+)", score_val)
        if m_num:
            try:
                val = float(m_num.group(1))
                if 0.0 <= val <= 10.0:
                    return val, score_val
            except ValueError:
                pass

    ds = vuln.get("database_specific") or {}
    cvss_field = ds.get("cvss") or ds.get("cvss_score") or ds.get("cvss_v3")
    if isinstance(cvss_field, (int, float)):
        return float(cvss_field), str(cvss_field)
    if isinstance(cvss_field, str):
        clean_cvss = re.sub(r"^CVSS:\d+\.\d+/?", "", cvss_field.strip(), flags=re.IGNORECASE)
        m = re.search(r"(\d+\.\d+)", clean_cvss)
        if m:
            return float(m.group(1)), cvss_field
    return None, None


def _finding_from_osv(
    vuln: Dict[str, Any], name: str, version: str, ecosystem: str, source_path: str, root: str
) -> Dict[str, Any]:
    vuln_id = str(vuln.get("id", "OSV-unknown"))
    database_specific = vuln.get("database_specific") or {}
    cwe_ids = [str(c) for c in (database_specific.get("cwe_ids") or [])] or [_CWE_OUTDATED]
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    summary = str(vuln.get("summary") or vuln.get("details") or "Vulnerabilidad conocida en una dependencia.")
    file_rel = _rel(source_path, root) if source_path else "manifest"
    references = [f"https://osv.dev/vulnerability/{vuln_id}"]
    references += [f"https://github.com/advisories/{alias}" for alias in aliases[:2]]

    # Parse CVSS score to determine severity as per requirement
    cvss_score, cvss_text = _parse_cvss_score_from_osv(vuln)
    if cvss_score is not None:
        if cvss_score >= 9.0:
            severity = "critical"
        elif cvss_score >= 7.0:
            severity = "high"
        elif cvss_score >= 4.0:
            severity = "medium"
        else:
            severity = "low"
    else:
        raw_sev = str(database_specific.get("severity", "")).lower()
        severity = raw_sev if raw_sev in ("critical", "high", "medium", "low") else "medium"

    # Extract fixed version from affected ranges
    fixed_versions = []
    for aff in (vuln.get("affected") or []):
        if not isinstance(aff, dict):
            continue
        for r in (aff.get("ranges") or []):
            if not isinstance(r, dict):
                continue
            for ev in (r.get("events") or []):
                if isinstance(ev, dict) and "fixed" in ev:
                    fixed_versions.append(str(ev["fixed"]))
    fixed_version_str = ", ".join(sorted(set(fixed_versions))) if fixed_versions else "No reportada"

    extra_data: Dict[str, Any] = {
        "package": {
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "fixed_version": fixed_version_str,
        },
    }
    if cvss_score is not None:
        extra_data["cvss"] = cvss_score
        if cvss_text:
            extra_data["cvss_vector"] = cvss_text

    return _make_finding(
        tool="osv-scanner",
        rule=f"osv-scanner/{name}/{vuln_id}",
        severity=severity,
        file=file_rel,
        line=None,
        title=f"{name}@{version} ({ecosystem}): {vuln_id}",
        problem=f"{name}@{version} es vulnerable: {summary}"[:400],
        solution=f"Actualizá {name} a la versión {fixed_version_str} o superior para corregir esta vulnerabilidad."
        if fixed_version_str != "No reportada"
        else "Actualizá la dependencia a una versión que corrija la vulnerabilidad y revisá los cambios de API antes de subir de versión.",
        cwe=cwe_ids,
        owasp=OWASP_OUTDATED,
        references=references,
        extra=extra_data,
    )


# ---------------------------------------------------------------------------
# pip-audit (contraste Python)
# ---------------------------------------------------------------------------

def _run_pip_audit(root: str, req_files: List[str], timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("pip-audit", "PIP_AUDIT_PATH")
    if not binary:
        return [], "unavailable"
    findings: List[Dict[str, Any]] = []
    for rel in req_files[:10]:
        stdout, code, status = _run_process(
            [binary, "-r", os.path.join(root, rel), "--format", "json",
             "--progress-spinner", "off"],
            cwd=root, timeout=timeout,
        )
        if status != "completed" or (code not in (0, 1) and not stdout):
            return findings, "error" if status == "completed" else status
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            continue
        for dep in data.get("dependencies", []) or []:
            name = str(dep.get("name", "unknown"))
            version = str(dep.get("version", "?"))
            for vuln in dep.get("vulns", []) or []:
                findings.append(_finding_from_pip_audit(vuln, name, version, rel))
    return findings, "completed"


def _finding_from_pip_audit(vuln: Dict[str, Any], name: str, version: str, req_rel: str) -> Dict[str, Any]:
    vuln_id = str(vuln.get("id", "UNKNOWN"))
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    fix_versions = ", ".join(str(v) for v in (vuln.get("fix_versions") or []))
    description = str(vuln.get("description") or "Vulnerabilidad conocida en la dependencia.")
    references = [f"https://github.com/advisories/{vuln_id}"] + [
        f"https://github.com/advisories/{alias}" for alias in aliases[:2]
    ]
    fix_text = f" Actualizá a: {fix_versions}." if fix_versions else ""
    return _make_finding(
        tool="pip-audit",
        rule=f"pip-audit/{name}/{vuln_id}",
        severity="medium",
        file=req_rel,
        line=None,
        title=f"{name}@{version}: {vuln_id}",
        problem=f"{name}@{version} es vulnerable: {description}"[:400],
        solution=f"Actualizá {name} a una versión parchada.{fix_text}",
        cwe=[_CWE_OUTDATED],
        owasp=OWASP_OUTDATED,
        references=references,
        extra={"package": {"name": name, "version": version, "ecosystem": "pypi", "fixed_version": fix_versions or "No reportada"}},
    )


# ---------------------------------------------------------------------------
# npm audit (contraste Node)
# ---------------------------------------------------------------------------

def _run_npm_audit(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("npm", "NPM_PATH")
    if not binary:
        return [], "unavailable"
    stdout, code, status = _run_process([binary, "audit", "--json"], cwd=root, timeout=timeout)
    if status != "completed" or (code not in (0, 1) and not stdout):
        return [], "error" if status == "completed" else status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    findings: List[Dict[str, Any]] = []
    for name, block in (data.get("vulnerabilities") or {}).items():
        if not isinstance(block, dict):
            continue
        severity = {"moderate": "medium"}.get(str(block.get("severity")), str(block.get("severity")))
        via_objects = [via for via in (block.get("via") or []) if isinstance(via, dict)]
        primary = via_objects[0] if via_objects else {}
        title = str(primary.get("title") or f"Vulnerabilidad en {name}")
        cwe_ids = [f"CWE-{cwe}" if isinstance(cwe, int) else str(cwe)
                   for cwe in (primary.get("cwes") or [])] or [_CWE_OUTDATED]
        fix = block.get("fixAvailable")
        fix_version = "No reportada"
        if fix:
            if isinstance(fix, dict):
                fix_version = str(fix.get("version") or "Disponible")
                fix_text = f" Actualizá {fix.get('name', name)} a {fix_version}."
            else:
                fix_version = "Disponible"
                fix_text = " Hay versión con fix disponible."
        else:
            fix_text = " No hay fix directo: revisá los rangos de versión declarados."
        findings.append(_make_finding(
            tool="npm-audit",
            rule=f"npm-audit/{name}",
            severity=severity,
            file="package-lock.json",
            line=None,
            title=f"{name}: {title}",
            problem=f"{title} (dependencia {name}, rango {block.get('range', '?')})."[:400],
            solution=fix_text,
            cwe=cwe_ids,
            owasp=OWASP_OUTDATED,
            references=[str(primary["url"])] if primary.get("url") else [],
            extra={"package": {"name": name, "version": str(block.get("range", "?")), "ecosystem": "npm", "fixed_version": fix_version}},
        ))
    return findings, "completed"


# ---------------------------------------------------------------------------
# Bandit (solo si hay Python)
# ---------------------------------------------------------------------------

_BANDIT_CWE = {
    "B324": "CWE-327", "B602": "CWE-78", "B605": "CWE-78",
    "B506": "CWE-502", "B608": "CWE-89", "B603": "CWE-78",
}
_BANDIT_OWASP = {
    "CWE-327": OWASP_SECRETS, "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-89": OWASP_INJECTION,
}


def _run_bandit(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("bandit", "BANDIT_PATH")
    if not binary:
        return [], "unavailable"
    stdout, code, status = _run_process([binary, "-r", root, "-f", "json", "-q"], timeout=timeout)
    if status != "completed" or (code not in (0, 1) and not stdout):
        return [], "error" if status == "completed" else status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    findings = [_finding_from_bandit(raw, root) for raw in data.get("results", []) or []]
    return findings, "completed"


def _finding_from_bandit(raw: Dict[str, Any], root: str) -> Dict[str, Any]:
    test_id = str(raw.get("test_id", ""))
    severity = str(raw.get("issue_severity", "")).lower()
    cwe_object = raw.get("issue_cwe") or {}
    cwe_id = cwe_object.get("id") if isinstance(cwe_object, dict) else None
    if cwe_id:
        cwe = [f"CWE-{int(cwe_id)}"]
    else:
        cwe = [_BANDIT_CWE.get(test_id)] if _BANDIT_CWE.get(test_id) else []
    owasp = _BANDIT_OWASP.get(cwe[0], OWASP_INJECTION) if cwe else OWASP_INJECTION
    return _make_finding(
        tool="bandit",
        rule=f"bandit/{test_id or raw.get('test_name', 'unknown')}",
        severity=severity,
        file=_rel(str(raw.get("filename", "")), root),
        line=raw.get("line_number"),
        title=f"{test_id} {raw.get('test_name', '')}".strip(),
        problem=str(raw.get("issue_text", "Riesgo detectado por Bandit."))[:400],
        solution="Revisá el patrón marcado y aplicá la alternativa segura recomendada por Bandit.",
        cwe=cwe,
        owasp=owasp,
        references=["https://bandit.readthedocs.io/"],
    )


# ---------------------------------------------------------------------------
# TruffleHog (secretos con verificación Valid/Invalid)
# ---------------------------------------------------------------------------

def _run_trufflehog(root: str, scan_git_history: bool, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("trufflehog", "TRUFFLEHOG_PATH")
    if not binary:
        return [], "unavailable"
    if scan_git_history and os.path.isdir(os.path.join(root, ".git")):
        cmd = [binary, "git", root, "--json", "--no-update"]
    else:
        cmd = [binary, "filesystem", root, "--json", "--no-update"]
    stdout, _code, status = _run_process(cmd, timeout=timeout)
    if status != "completed":
        return [], status
    findings: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            findings.append(_finding_from_trufflehog(payload, root))
    return findings, "completed"


def _finding_from_trufflehog(raw: Dict[str, Any], root: str) -> Dict[str, Any]:
    detector = str(raw.get("DetectorName") or raw.get("DetectorType") or "secret")
    verified = raw.get("Verified")
    verification = "valid" if verified is True else ("invalid" if verified is False else "unknown")
    data = ((raw.get("SourceMetadata") or {}).get("Data") or {})
    file_value = str(data.get("File") or "")
    file_rel = _rel(file_value, root) if file_value else "unknown"
    line = data.get("Line") if isinstance(data.get("Line"), int) else None
    verdict_text = {"valid": "Válida (activa)", "invalid": "Inválida (inactiva)"}.get(verification, "sin verificar")
    return _make_finding(
        tool="trufflehog",
        rule=f"trufflehog/{detector}",
        severity="critical" if verification == "valid" else ("medium" if verification == "invalid" else "high"),
        file=file_rel,
        line=line,
        title=f"Secreto {detector} — {verdict_text}",
        problem=(f"Se detectó un posible secreto de tipo {detector} y TruffleHog lo verificó contra el proveedor: "
                 f"{verdict_text.lower()}. Por seguridad el valor del secreto no se incluye en el reporte."),
        solution="Revocá y rotá la credencial, eliminá el secreto del código y del historial de git, y pasá a un gestor de secretos.",
        cwe=["CWE-798"],
        owasp=OWASP_SECRETS,
        references=["https://github.com/trufflesecurity/trufflehog"],
        extra={"verification": verification},
    )


# ---------------------------------------------------------------------------
# IaC: Checkov o Trivy (Terraform / CloudFormation) · Dockerfiles: Hadolint o Trivy
# ---------------------------------------------------------------------------

def _run_checkov(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("checkov", "CHECKOV_PATH")
    if not binary:
        return [], "unavailable"
    stdout, _code, status = _run_process(
        [binary, "-d", root, "-o", "json", "--quiet", "--skip-download",
         "--framework", "terraform,cloudformation"],
        timeout=timeout,
    )
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    failed = (data.get("results") or {}).get("failed_checks") or []
    return [_finding_from_checkov(check, root) for check in failed], "completed"


def _finding_from_checkov(check: Dict[str, Any], root: str) -> Dict[str, Any]:
    line_range = check.get("file_line_range") or [None]
    severity = str(check.get("severity", "")).lower()
    references = [str(check["guideline"])] if check.get("guideline") else []
    return _make_finding(
        tool="checkov",
        rule=f"checkov/{check.get('check_id', 'unknown')}",
        severity=severity,
        file=_rel(str(check.get("file_path", "")), root),
        line=line_range[0] if isinstance(line_range[0], int) else None,
        title=str(check.get("check_name") or check.get("check_id", "Configuración insegura")),
        problem=f"Recurso {check.get('resource', '?')}: {check.get('check_name', 'configuración insegura en IaC.')}"[:400],
        solution=str(check.get("guideline") or "Corregí la configuración de IaC según la guía del check."),
        cwe=[_CWE_CONFIG],
        owasp=OWASP_MISCONFIG,
        references=references,
        extra={"resource": str(check.get("resource", ""))},
    )


def _run_trivy_config(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("trivy", "TRIVY_PATH")
    if not binary:
        return [], "unavailable"
    stdout, _code, status = _run_process([binary, "config", "--format", "json", "--quiet", root], timeout=timeout)
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    findings: List[Dict[str, Any]] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target", ""))
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append(_finding_from_trivy(misconfig, target, root))
    return findings, "completed"


def _finding_from_trivy(misconfig: Dict[str, Any], target: str, root: str) -> Dict[str, Any]:
    avd_id = str(misconfig.get("ID", "unknown"))
    cause = misconfig.get("CauseMetadata") or {}
    line = cause.get("StartLine") if isinstance(cause.get("StartLine"), int) else None
    cwe = ["CWE-494"] if avd_id == "AVD-DS-0002" else [_CWE_CONFIG]
    return _make_finding(
        tool="trivy",
        rule=f"trivy/{avd_id}",
        severity=str(misconfig.get("Severity", "")).lower(),
        file=_rel(target, root) if target else "unknown",
        line=line,
        title=str(misconfig.get("Title", "Configuración insegura")),
        problem=str(misconfig.get("Description", "Configuración insegura detectada por Trivy."))[:400],
        solution=str(misconfig.get("Resolution") or "Aplicá la corrección sugerida por el check de Trivy."),
        cwe=cwe,
        owasp=OWASP_MISCONFIG,
        references=[str(ref) for ref in (misconfig.get("References") or [])[:3]],
    )


def _run_hadolint(root: str, dockerfiles: List[str], timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("hadolint", "HADOLINT_PATH")
    if not binary:
        return [], "unavailable"
    targets = dockerfiles[:20]
    stdout, _code, status = _run_process([binary, "--format", "json"] + targets, cwd=root, timeout=timeout)
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return [], "error"
    if not isinstance(data, list):
        return [], "error"
    return [_finding_from_hadolint(item, root) for item in data], "completed"


def _finding_from_hadolint(item: Dict[str, Any], root: str) -> Dict[str, Any]:
    code = str(item.get("code", "DL0000"))
    severity = {"error": "high", "warning": "medium", "info": "low"}.get(str(item.get("severity", "")), "medium")
    cwe = ["CWE-250"] if code == "DL3002" else [_CWE_CONFIG]
    return _make_finding(
        tool="hadolint",
        rule=f"hadolint/{code}",
        severity=severity,
        file=_rel(str(item.get("file", "")), root),
        line=item.get("line") if isinstance(item.get("line"), int) else None,
        title=f"{code}: {item.get('message', 'Problema de construcción en Dockerfile')}"[:200],
        problem=str(item.get("message", "Problema de seguridad en el Dockerfile."))[:400],
        solution="Corregí la instrucción del Dockerfile según la regla " + code + " (https://github.com/hadolint/hadolint/wiki).",
        cwe=cwe,
        owasp=OWASP_MISCONFIG,
        references=[f"https://github.com/hadolint/hadolint/wiki/{code}"],
    )


# ---------------------------------------------------------------------------
# zizmor (GitHub Actions)
# ---------------------------------------------------------------------------

def _run_zizmor(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("zizmor", "ZIZMOR_PATH")
    if not binary:
        return [], "unavailable"
    workflows_dir = os.path.join(root, ".github", "workflows")
    target = workflows_dir if os.path.isdir(workflows_dir) else root
    stdout, _code, status = _run_process([binary, "--format", "json", target], timeout=timeout)
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return [], "error"
    if not isinstance(data, list):
        return [], "error"
    return [_finding_from_zizmor(item, root) for item in data if isinstance(item, dict)], "completed"


def _finding_from_zizmor(item: Dict[str, Any], root: str) -> Dict[str, Any]:
    ident = str(item.get("ident") or item.get("audit") or "workflow-risk")
    description = str(item.get("description") or item.get("message") or "Riesgo detectado en el workflow.")
    location = item.get("location") or {}
    file_rel = _rel(str(location.get("workflow") or ""), root) or ".github/workflows"
    confidence = str(item.get("confidence", "")).lower()
    is_injection = "injection" in ident
    return _make_finding(
        tool="zizmor",
        rule=f"zizmor/{ident}",
        severity="medium" if confidence in ("high", "") else "low",
        file=file_rel,
        line=None,
        title=f"GitHub Actions: {ident}",
        problem=description[:400],
        solution="Corregí el workflow según la guía de zizmor para el check " + ident + ".",
        cwe=["CWE-94"] if is_injection else [_CWE_CONFIG],
        owasp=OWASP_INJECTION if is_injection else OWASP_MISCONFIG,
        references=["https://woodruffw.github.io/zizmor/"],
    )


# ---------------------------------------------------------------------------
# Dependabot
# ---------------------------------------------------------------------------

def _dependabot_finding() -> Dict[str, Any]:
    return _make_finding(
        tool="dependabot",
        rule="dependabot/missing-config",
        severity="low",
        file=".github/dependabot.yml",
        line=None,
        title="Dependabot no está configurado",
        problem="El repositorio no configura Dependabot: las dependencias no reciben actualizaciones automáticas de seguridad.",
        solution="Agregá .github/dependabot.yml con un bloque 'package-ecosystem' y 'schedule' por cada gestor detectado.",
        cwe=[_CWE_OUTDATED],
        owasp=OWASP_OUTDATED,
        references=["https://docs.github.com/en/code-security/dependabot"],
    )


# ---------------------------------------------------------------------------
# SBOM (Syft) y licencias (ScanCode)
# ---------------------------------------------------------------------------

def _run_syft(root: str, timeout: int) -> Tuple[Optional[Dict[str, Any]], str]:
    binary = _tool_bin("syft", "SYFT_PATH")
    if not binary:
        return None, "unavailable"
    stdout, _code, status = _run_process([binary, f"dir:{root}", "-o", "cyclonedx-json"], timeout=timeout)
    if status != "completed":
        return None, status
    try:
        document = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return None, "error"
    components = document.get("components") or []
    packages = []
    for component in components[:_MAX_SBOM_PACKAGES]:
        licenses = []
        for entry in component.get("licenses") or []:
            license_info = entry.get("license") or {}
            value = license_info.get("id") or license_info.get("name")
            if value and str(value) not in licenses:
                licenses.append(str(value))
        packages.append({
            "name": str(component.get("name", "")),
            "version": str(component.get("version", "")),
            "licenses": licenses[:5],
        })
    return {
        "tool": "syft",
        "format": "cyclonedx-json",
        "total_packages": len(components),
        "packages": packages,
    }, "completed"


def _run_scancode(root: str, timeout: int) -> Tuple[Optional[Dict[str, Any]], str]:
    binary = _tool_bin("scancode", "SCANCODE_PATH")
    if not binary:
        return None, "unavailable"
    stdout, _code, status = _run_process(
        [binary, root, "--license", "--json-pp", "-", "--threads", "2"], timeout=timeout,
    )
    if status != "completed":
        return None, status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return None, "error"
    counts: Dict[str, int] = {}
    files = data.get("files") or []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        for license_info in entry.get("licenses") or []:
            key = str((license_info or {}).get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + 1
    licenses = [
        {"license": key, "files": count}
        for key, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)
    ][:_MAX_LICENSES]
    return {"tool": "scancode", "total_files": len(files), "licenses": licenses}, "completed"


# ---------------------------------------------------------------------------
# OpenSSF Scorecard
# ---------------------------------------------------------------------------

def _run_scorecard(root: str, timeout: int) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], str]:
    binary = _tool_bin("scorecard", "SCORECARD_PATH")
    if not binary:
        return None, [], "unavailable"
    stdout, _code, status = _run_process([binary, "--local", root, "--format", "json"], timeout=timeout)
    if status != "completed":
        return None, [], status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return None, [], "error"
    checks = []
    findings: List[Dict[str, Any]] = []
    for check in (data.get("checks") or [])[:_MAX_SCORECARD_CHECKS]:
        if not isinstance(check, dict):
            continue
        name = str(check.get("name", "unknown"))
        score = check.get("score")
        reason = str(check.get("reason", ""))
        checks.append({"name": name, "score": score, "reason": reason[:240]})
        if score == 0:
            findings.append(_make_finding(
                tool="scorecard",
                rule=f"scorecard/{name}",
                severity="medium",
                file=".",
                line=None,
                title=f"OpenSSF Scorecard: {name} = 0",
                problem=reason[:400] or f"El check {name} de OpenSSF Scorecard obtuvo puntaje 0 en el repositorio.",
                solution="Revisá la documentación del check en https://github.com/ossf/scorecard y aplicá la mitigación sugerida.",
                cwe=[_CWE_OUTDATED],
                owasp=OWASP_OUTDATED,
                references=["https://github.com/ossf/scorecard"],
            ))
    return {
        "tool": "openssf-scorecard",
        "score": data.get("score"),
        "checks": checks,
    }, findings, "completed"


# ---------------------------------------------------------------------------
# Dependencias declaradas sin uso: depcheck (Node) / deptry (Python)
# ---------------------------------------------------------------------------

def _run_depcheck(root: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("depcheck", "DEPCHECK_PATH")
    if not binary:
        return [], "unavailable"
    stdout, _code, status = _run_process([binary, "--json"], cwd=root, timeout=timeout)
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    findings = [_unused_dependency_finding("depcheck", str(name), "package.json")
                for name in (data.get("dependencies") or [])[:50] if str(name)]
    return findings, "completed"


def _run_deptry(root: str, dep_file: str, timeout: int) -> Tuple[List[Dict[str, Any]], str]:
    binary = _tool_bin("deptry", "DEPTRY_PATH")
    if not binary:
        return [], "unavailable"
    stdout, _code, status = _run_process([binary, ".", "--json"], cwd=root, timeout=timeout)
    if status != "completed":
        return [], status
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [], "error"
    payload = data.get("data") if isinstance(data.get("data"), dict) else data
    unused = (payload.get("unused") or []) if isinstance(payload, dict) else []
    findings = []
    for item in unused[:50]:
        name = item if isinstance(item, str) else str((item or {}).get("module") or "")
        if name:
            findings.append(_unused_dependency_finding("deptry", name, dep_file))
    return findings, "completed"


def _unused_dependency_finding(tool: str, name: str, file: str) -> Dict[str, Any]:
    return _make_finding(
        tool=tool,
        rule=f"{tool}/{name}",
        severity="low",
        file=file,
        line=None,
        title=f"Dependencia declarada sin uso: {name}",
        problem=f"'{name}' está declarada en {file} pero no se usa en el código: agranda la superficie de ataque y la instalación sin aportar valor.",
        solution=f"Eliminá '{name}' del manifiesto o documentá por qué se mantiene.",
        cwe=[_CWE_OUTDATED],
        owasp=OWASP_OUTDATED,
    )


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def _severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(str(severity), 1)


def _dep_identity(finding: Dict[str, Any]) -> Tuple[str, str]:
    parts = str(finding.get("rule", "")).split("/")
    if len(parts) >= 3:
        return parts[-2].lower(), parts[-1].upper()
    return str(finding.get("rule", "")), ""


def _same_issue(first: Dict[str, Any], second: Dict[str, Any]) -> bool:
    """True si dos hallazgos describen el mismo problema (mismo archivo, misma
    CWE y líneas contiguas —o, para dependencias, mismo paquete y advisory)."""
    if str(first.get("file", "")).lower() != str(second.get("file", "")).lower():
        return False
    if _cwe_key(first) != _cwe_key(second):
        return False
    line_a, line_b = first.get("line"), second.get("line")
    if isinstance(line_a, int) and isinstance(line_b, int):
        return abs(line_a - line_b) <= 2
    if not line_a and not line_b:
        return _dep_identity(first) == _dep_identity(second)
    return False


def merge_tool_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fusiona detecciones repetidas entre herramientas: cada hallazgo resultante
    queda con la unión de las herramientas que lo detectaron y la severidad más
    alta. Conserva el texto y regla de la primera detección (motor primario)."""
    if len(findings) > _MERGE_LIMIT:
        for index, finding in enumerate(findings, start=1):
            finding["id"] = index
            finding.setdefault("tools", ["unknown"])
        return findings
    merged: List[Dict[str, Any]] = []
    for finding in findings:
        target = next((existing for existing in merged if _same_issue(existing, finding)), None)
        if target is None:
            merged.append(finding)
            continue
        for tool in finding.get("tools", []):
            if tool not in target["tools"]:
                target["tools"].append(tool)
        if finding.get("verification") and not target.get("verification"):
            target["verification"] = finding["verification"]
        if _severity_rank(finding.get("severity")) > _severity_rank(target.get("severity")):
            target["severity"] = finding.get("severity")
        for field, source in (finding.get("sources") or {}).items():
            target["sources"].setdefault(field, source)
        for reference in finding.get("references") or []:
            if reference not in target["references"] and len(target["references"]) < 6:
                target["references"].append(reference)
    for index, finding in enumerate(merged, start=1):
        finding["id"] = index
        finding.setdefault("tools", ["unknown"])
    return merged


def run_tools(
    root: str,
    stack: Optional[Dict[str, Any]] = None,
    scan_git_history: bool = False,
    timeout_budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Run every optional tool that applies to the detected stack. Never raises:
    per-tool failures are recorded in the tools status map. Returns findings
    (each stamped with its tool), the tools map, the stack and the extra
    reports (SBOM, licenses, scorecard)."""
    detected_stack = stack or detect_stack(root)
    findings: List[Dict[str, Any]] = []
    tools: Dict[str, str] = {}
    extras: Dict[str, Any] = {"sbom": None, "licenses": None, "scorecard": None}

    def run_findings(name: str, fn, condition: bool = True) -> None:
        if not condition:
            tools[name] = "skipped"
            return
        try:
            result, status = fn()
        except Exception:
            tools[name] = "error"
            return
        tools[name] = status
        if isinstance(result, list):
            findings.extend(result)

    def run_report(name: str, key: str, fn, condition: bool = True) -> None:
        if not condition:
            tools[name] = "skipped"
            return
        try:
            result, status = fn()
        except Exception:
            tools[name] = "error"
            return
        tools[name] = status
        if isinstance(result, dict):
            extras[key] = result

    iac_applicable = bool(detected_stack["terraform"] or detected_stack["cloudformation"])
    trivy_ran = False

    if iac_applicable:
        if _tool_bin("checkov", "CHECKOV_PATH"):
            run_findings("checkov", lambda: _run_checkov(root, _clamp_timeout(600, timeout_budget)))
        elif _tool_bin("trivy", "TRIVY_PATH"):
            run_findings("trivy", lambda: _run_trivy_config(root, _clamp_timeout(600, timeout_budget)))
            trivy_ran = True
        else:
            tools["checkov"] = "unavailable"
            tools["trivy"] = "unavailable"
    else:
        tools["checkov"] = "skipped"
        tools["trivy"] = "skipped"

    if detected_stack["dockerfiles"]:
        if _tool_bin("hadolint", "HADOLINT_PATH"):
            run_findings("hadolint", lambda: _run_hadolint(
                root, detected_stack["dockerfiles"], _clamp_timeout(120, timeout_budget)))
        elif _tool_bin("trivy", "TRIVY_PATH") and not trivy_ran:
            run_findings("trivy", lambda: _run_trivy_config(root, _clamp_timeout(600, timeout_budget)))
        else:
            tools["hadolint"] = "unavailable" if not _tool_bin("hadolint", "HADOLINT_PATH") else "skipped"
    else:
        tools["hadolint"] = "skipped"

    run_findings("osv-scanner", lambda: _run_osv(root, _clamp_timeout(300, timeout_budget)),
                 condition=bool(detected_stack["dependency_files"]))
    run_findings("pip-audit", lambda: _run_pip_audit(
        root, detected_stack["requirements_files"], _clamp_timeout(300, timeout_budget)),
        condition=bool(detected_stack["requirements_files"]))
    run_findings("npm-audit", lambda: _run_npm_audit(root, _clamp_timeout(300, timeout_budget)),
                 condition=detected_stack["package_lock"])
    run_findings("bandit", lambda: _run_bandit(root, _clamp_timeout(300, timeout_budget)),
                 condition=detected_stack["has_python"])
    run_findings("trufflehog", lambda: _run_trufflehog(
        root, scan_git_history, _clamp_timeout(300, timeout_budget)))
    run_findings("zizmor", lambda: _run_zizmor(root, _clamp_timeout(120, timeout_budget)),
                 condition=bool(detected_stack["github_workflows"]))
    run_report("syft", "sbom", lambda: _run_syft(root, _clamp_timeout(600, timeout_budget)),
               condition=bool(detected_stack["dependency_files"]))
    run_report("scancode", "licenses", lambda: _run_scancode(root, _clamp_timeout(600, timeout_budget)),
               condition=bool(detected_stack["languages"]))
    scorecard_outcome: Dict[str, Any] = {}

    def _scorecard_runner():
        summary, scorecard_findings, status = _run_scorecard(root, _clamp_timeout(300, timeout_budget))
        scorecard_outcome["summary"] = summary
        return scorecard_findings, status

    run_findings("scorecard", _scorecard_runner, condition=bool(detected_stack["dependency_files"]))
    extras["scorecard"] = scorecard_outcome.get("summary")
    run_findings("depcheck", lambda: _run_depcheck(root, _clamp_timeout(180, timeout_budget)),
                 condition=detected_stack["has_node"] and detected_stack["package_lock"])
    python_dep_file = (detected_stack["requirements_files"][0]
                       if detected_stack["requirements_files"]
                       else ("pyproject.toml" if "pyproject.toml" in detected_stack["dependency_files"]
                             else "requirements.txt"))
    run_findings("deptry", lambda: _run_deptry(root, python_dep_file, _clamp_timeout(180, timeout_budget)),
                 condition=detected_stack["has_python"] and bool(detected_stack["dependency_files"]))

    if detected_stack["dependabot"]:
        tools["dependabot"] = "present"
    else:
        tools["dependabot"] = "missing"
        findings.append(_dependabot_finding())

    return {
        "findings": findings,
        "tools": tools,
        "stack": detected_stack,
        "sbom": extras["sbom"],
        "licenses": extras["licenses"],
        "scorecard": extras["scorecard"],
    }
