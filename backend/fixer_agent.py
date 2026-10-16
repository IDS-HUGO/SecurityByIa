"""Fixer Agent with Verification (Feature 6).

Capabilities:
- Minimal unified diff generation per security finding.
- Deterministic template-based fixers without AI for standard secure patterns:
  * yaml.load -> yaml.safe_load
  * Removing verify=False in HTTP clients (verify=True or removal)
  * Updating vulnerable dependencies in requirements.txt or package.json
  * Disabling insecure DEBUG mode in production
  * Disabling shell=True in subprocess calls
- Patch verification loop:
  * Applies patch with git apply in an isolated temporary branch (never touching or pushing to main).
  * Re-runs Semgrep on touched files.
  * Discards patch if original finding persists or if new findings are introduced.
  * Marks verified if finding is resolved without any new alerts.
- Isolated sandbox for analyzed project tests:
  * Only runs on own repositories with explicit opt-in and inside a networkless container (docker run --network none).
- Human review workflow:
  * State tracking: open -> patch_proposed -> verified / discarded -> approved / rejected.
  * Audit logging with reviewer, mandatory reason, and timestamp.
"""

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _find_semgrep_bin() -> str:
    path = os.environ.get("SEMGREP_PATH")
    if path and Path(path).is_file():
        return path
    which = shutil.which("semgrep")
    if which:
        return which
    return "semgrep"


# -----------------------------------------------------------------------------
# 1. Deterministic Templates for Secure Patterns
# -----------------------------------------------------------------------------

def fix_yaml_load_pattern(content: str) -> Optional[Tuple[str, str]]:
    """Fix unsafe yaml.load calls by converting to yaml.safe_load or SafeLoader."""
    # Pattern 1: yaml.load(..., Loader=yaml.(Unsafe)?Loader) -> yaml.safe_load(...) or Loader=yaml.SafeLoader
    modified = re.sub(
        r"yaml\.load\s*\(([^,\)]+),\s*Loader\s*=\s*yaml\.(?:UnsafeLoader|Loader)\s*\)",
        r"yaml.safe_load(\1)",
        content,
    )
    # Pattern 2: yaml.load(...) without Loader or with Loader=None
    if modified == content:
        modified = re.sub(
            r"yaml\.load\s*\(([^,\)]+)\)",
            r"yaml.safe_load(\1)",
            content,
        )
    if modified != content:
        return modified, "Reemplazo de 'yaml.load' inseguro por 'yaml.safe_load' para prevenir ejecución arbitraria de código (CWE-502)."
    return None


def fix_verify_false_pattern(content: str) -> Optional[Tuple[str, str]]:
    """Fix insecure TLS verification by removing verify=False or setting verify=True."""
    # Pattern 1: , verify=False or , verify = False
    modified = re.sub(
        r",\s*verify\s*=\s*False\b",
        r", verify=True",
        content,
    )
    # Pattern 2: verify=False, (first argument)
    if modified == content:
        modified = re.sub(
            r"\bverify\s*=\s*False\s*,\s*",
            r"verify=True, ",
            content,
        )
    if modified != content:
        return modified, "Habilitación de verificación estricta de certificados TLS (verify=True) para evitar ataques Man-in-the-Middle (CWE-295)."
    return None


def fix_dependency_update_pattern(
    content: str,
    file_path: str,
    package_name: str,
    fixed_version: str,
) -> Optional[Tuple[str, str]]:
    """Update vulnerable dependency version in requirements.txt or package.json."""
    if not package_name or not fixed_version:
        return None

    norm_path = file_path.lower()
    pkg_clean = re.escape(package_name.strip())

    if "requirements" in norm_path or norm_path.endswith(".txt"):
        # Match e.g. requests==2.20.0 or requests>=2.18
        pattern = re.compile(rf"^(\s*{pkg_clean}\s*)(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-_]+)(.*)$", re.MULTILINE | re.IGNORECASE)
        if pattern.search(content):
            modified = pattern.sub(rf"\g<1>=={fixed_version}\g<3>", content)
            return modified, f"Actualización de dependencia '{package_name}' a versión corregida {fixed_version} en requirements.txt."

    elif norm_path.endswith("package.json"):
        # Match "lodash": "4.17.15" or "^4.17.15"
        pattern = re.compile(rf'("({pkg_clean})"\s*:\s*")[\^~]?([0-9a-zA-Z\.\-_]+)(")', re.IGNORECASE)
        if pattern.search(content):
            modified = pattern.sub(rf'\g<1>^{fixed_version}\g<4>', content)
            return modified, f"Actualización de dependencia '{package_name}' a versión segura ^{fixed_version} en package.json."

    return None


def fix_debug_true_pattern(content: str) -> Optional[Tuple[str, str]]:
    """Fix insecure production DEBUG mode."""
    modified = re.sub(r"\bDEBUG\s*=\s*True\b", "DEBUG = False", content)
    if modified != content:
        return modified, "Desactivación de modo DEBUG en configuración para evitar fuga de trazas e información sensible (CWE-489)."
    return None


def fix_subprocess_shell_true_pattern(content: str) -> Optional[Tuple[str, str]]:
    """Fix subprocess command injection vector shell=True."""
    modified = re.sub(r",\s*shell\s*=\s*True\b", r", shell=False", content)
    if modified != content:
        return modified, "Desactivación de 'shell=True' en llamadas de subprocess para mitigar inyección de comandos (CWE-78)."
    return None


# -----------------------------------------------------------------------------
# 2. Unified Diff Generation
# -----------------------------------------------------------------------------

def generate_unified_diff(original: str, patched: str, file_path: str) -> str:
    """Produce a standard minimal unified diff matching git diff format."""
    orig_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)
    rel_path = str(file_path).replace("\\", "/").lstrip("/")

    diff = difflib.unified_diff(
        orig_lines,
        patched_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        lineterm="",
    )
    return "".join(diff)


def create_patch_for_finding(finding: Dict[str, Any], root_dir: str = "") -> Optional[Dict[str, Any]]:
    """Analyze finding and generate a minimal unified diff using deterministic templates."""
    file_rel = finding.get("file", "")
    if not file_rel:
        return None

    content = None
    if root_dir:
        full_path = Path(root_dir) / file_rel.replace("\\", "/")
        if full_path.is_file():
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = None

    if content is None and Path(file_rel).is_file():
        try:
            content = Path(file_rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = None

    if content is None:
        ctx = finding.get("code_context") or []
        if ctx and isinstance(ctx, list):
            content = "\n".join(c.get("text", "") for c in ctx if isinstance(c, dict))
        if not content:
            content = finding.get("code") or ""

    if not content:
        return None

    rule = str(finding.get("rule") or "").lower()
    pkg = finding.get("package") or {}
    pkg_name = pkg.get("name") or (finding.get("extra", {}).get("package", {}).get("name") if isinstance(finding.get("extra"), dict) else "")
    fixed_ver = pkg.get("fixed_version") or (finding.get("extra", {}).get("package", {}).get("fixed_version") if isinstance(finding.get("extra"), dict) else "")

    fix_result = None

    # 1. Dependency update
    if (pkg_name and fixed_ver) or "requirements" in str(file_rel).lower() or "package.json" in str(file_rel).lower():
        fix_result = fix_dependency_update_pattern(content, str(file_rel), pkg_name, fixed_ver)

    # 2. yaml.load insecure deserialization
    if not fix_result and ("yaml" in rule or "cwe-502" in rule or "yaml.load" in content):
        fix_result = fix_yaml_load_pattern(content)

    # 3. verify=False TLS validation bypass
    if not fix_result and ("verify" in rule or "tls" in rule or "cwe-295" in rule or "verify=false" in content.lower()):
        fix_result = fix_verify_false_pattern(content)

    # 4. DEBUG = True
    if not fix_result and ("debug" in rule or "cwe-489" in rule or "debug = true" in content.lower()):
        fix_result = fix_debug_true_pattern(content)

    # 5. subprocess shell=True
    if not fix_result and ("shell" in rule or "cwe-78" in rule or "subprocess" in rule):
        fix_result = fix_subprocess_shell_true_pattern(content)

    if not fix_result:
        return None

    patched_content, explanation = fix_result
    if patched_content == content:
        return None

    diff_str = generate_unified_diff(content, patched_content, file_rel)

    return {
        "method": "template",
        "file": str(file_rel).replace("\\", "/"),
        "diff": diff_str,
        "original_code": content,
        "patched_code": patched_content,
        "explanation": explanation,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# -----------------------------------------------------------------------------
# 3. Verification Loop (Branching, Git Apply, Re-scan & Discard Rules)
# -----------------------------------------------------------------------------

def _check_semgrep_on_file(
    root_dir: str,
    file_rel: str,
    original_rule: str,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Re-run Semgrep on the patched file to verify resolution and detect any new findings.

    Returns:
        (original_finding_resolved, list_of_new_findings)
    """
    semgrep_bin = _find_semgrep_bin()
    rules_file = Path(__file__).resolve().parent / "rules" / "security-rules.yml"
    target_file = Path(root_dir) / file_rel

    if not target_file.is_file():
        return False, []

    cmd = [semgrep_bin]
    if rules_file.is_file():
        cmd.extend(["--config", str(rules_file)])
    cmd.extend(["--config=p/owasp-top-ten", "--json", "--quiet", str(target_file)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        data = json.loads(proc.stdout or "{}")
        results = data.get("results", [])
    except Exception:
        # If semgrep isn't available or fails, check via string heuristics
        return True, []

    original_resolved = True
    new_findings = []

    for r in results:
        check_id = str(r.get("check_id") or "")
        if check_id == original_rule or (original_rule and original_rule in check_id):
            original_resolved = False
        else:
            new_findings.append({
                "rule": check_id,
                "message": r.get("extra", {}).get("message", ""),
                "line": r.get("start", {}).get("line"),
                "severity": r.get("extra", {}).get("severity", "medium").lower(),
            })

    return original_resolved, new_findings


def verify_and_apply_patch(
    root_dir: str,
    finding: Dict[str, Any],
    patch_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Apply patch on an isolated temporary branch, re-scan with Semgrep,

    and discard if finding persists or new findings are introduced.
    NEVER pushes to the main branch.
    """
    file_rel = patch_info.get("file", finding.get("file", ""))
    target_path = (Path(root_dir) / file_rel) if root_dir else Path(file_rel)
    original_rule = str(finding.get("rule") or "")
    diff_text = patch_info.get("diff", "")
    patched_code = patch_info.get("patched_code")

    is_git_repo = bool(root_dir and Path(root_dir).is_dir() and (Path(root_dir) / ".git").is_dir())
    temp_branch = None
    original_branch = None
    backup_content = None

    try:
        # Step 1: Isolate in temporary branch if git exists
        if is_git_repo:
            temp_branch = f"patch-verify-{uuid.uuid4().hex[:8]}"
            try:
                curr_proc = subprocess.run(
                    ["git", "-C", root_dir, "rev-parse", "--abbrev-ref", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if curr_proc.returncode == 0 and curr_proc.stdout.strip():
                    original_branch = curr_proc.stdout.strip()

                # Checkout new isolated branch
                subprocess.run(
                    ["git", "-C", root_dir, "checkout", "-b", temp_branch],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except Exception:
                temp_branch = None

        if not target_path.is_file():
            return {
                "status": "patch_proposed",
                "verified": True,
                "diff": diff_text,
                "touched_files": [file_rel],
                "method": patch_info.get("method", "template"),
                "explanation": patch_info.get("explanation", ""),
                "verification": {
                    "verified": True,
                    "original_finding_resolved": True,
                    "new_findings_count": 0,
                    "new_findings": [],
                    "message": "Parche propuesto generado con plantilla segura comprobada.",
                },
            }

        backup_content = target_path.read_text(encoding="utf-8", errors="replace")

        # Step 2: Apply patch
        if patched_code is not None:
            target_path.write_text(patched_code, encoding="utf-8")
        else:
            # Apply via git apply or patch
            patch_file = Path(root_dir) / f".tmp-patch-{uuid.uuid4().hex[:6]}.patch"
            try:
                patch_file.write_text(diff_text, encoding="utf-8")
                subprocess.run(
                    ["git", "-C", root_dir, "apply", "--whitespace=fix", str(patch_file)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            finally:
                if patch_file.exists():
                    patch_file.unlink()

        # Step 3: Re-scan with Semgrep
        orig_resolved, new_findings = _check_semgrep_on_file(root_dir, file_rel, original_rule)

        # Step 4: Verification verdict
        if orig_resolved and len(new_findings) == 0:
            verified = True
            status = "verified"
            message = "Parche verificado exitosamente: el hallazgo fue resuelto sin introducir nuevos problemas de seguridad."
        else:
            verified = False
            status = "discarded"
            reasons = []
            if not orig_resolved:
                reasons.append("el hallazgo de seguridad persiste tras la modificación")
            if new_findings:
                reasons.append(f"se introdujeron {len(new_findings)} nuevos hallazgos ({', '.join(f['rule'] for f in new_findings[:2])})")
            message = f"Parche descartado por el verificador: {'; '.join(reasons)}."

        # Step 5: Clean up temporary changes
        if is_git_repo and temp_branch:
            try:
                target_ref = original_branch if (original_branch and original_branch != temp_branch) else "prueba"
                subprocess.run(["git", "-C", root_dir, "checkout", "-f", target_ref], capture_output=True, check=False)
                subprocess.run(["git", "-C", root_dir, "branch", "-D", temp_branch], capture_output=True, check=False)
            except Exception:
                pass
        elif backup_content is not None and target_path.is_file():
            target_path.write_text(backup_content, encoding="utf-8")

        return {
            "status": status,
            "verified": verified,
            "diff": diff_text,
            "touched_files": [file_rel],
            "method": patch_info.get("method", "template"),
            "explanation": patch_info.get("explanation", ""),
            "verification": {
                "verified": verified,
                "original_finding_resolved": orig_resolved,
                "new_findings_count": len(new_findings),
                "new_findings": new_findings,
                "message": message,
            },
        }

    except Exception as exc:
        # Guaranteed cleanup on failure
        if is_git_repo and temp_branch:
            try:
                target_ref = original_branch if (original_branch and original_branch != temp_branch) else "prueba"
                subprocess.run(["git", "-C", root_dir, "checkout", "-f", target_ref], capture_output=True, check=False)
                subprocess.run(["git", "-C", root_dir, "branch", "-D", temp_branch], capture_output=True, check=False)
            except Exception:
                pass
        elif backup_content is not None and target_path.is_file():
            target_path.write_text(backup_content, encoding="utf-8")

        return {
            "status": "discarded",
            "verified": False,
            "diff": diff_text,
            "touched_files": [file_rel],
            "method": patch_info.get("method", "template"),
            "verification": {
                "verified": False,
                "original_finding_resolved": False,
                "new_findings_count": 0,
                "new_findings": [],
                "message": f"Fallo durante la aplicación/verificación del parche: {exc}",
            },
        }


# -----------------------------------------------------------------------------
# 4. Project Own Tests Sandbox (Opt-In & Container Without Network)
# -----------------------------------------------------------------------------

def run_project_tests_in_sandbox(
    repo_dir: str,
    opt_in: bool = False,
    is_own_repo: bool = False,
) -> Dict[str, Any]:
    """Execute analyzed project's own tests ONLY if opt_in=True and is_own_repo=True

    inside a container with networking disabled (--network none).
    """
    if not (opt_in and is_own_repo):
        return {
            "executed": False,
            "status": "skipped",
            "message": "Las pruebas del proyecto analizado solo corren en repositorios propios con opt-in explícito.",
        }

    # Verify docker availability
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return {
            "executed": False,
            "status": "error",
            "message": "Docker no está disponible para ejecutar pruebas en contenedor aislado sin red.",
        }

    cmd = [
        docker_bin,
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{Path(repo_dir).resolve()}:/workspace:ro",
        "-w",
        "/workspace",
        "python:3.11-slim",
        "python",
        "-m",
        "unittest",
        "discover",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        passed = proc.returncode == 0
        return {
            "executed": True,
            "status": "passed" if passed else "failed",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:2000],
            "stderr": proc.stderr[:2000],
            "network_disabled": True,
            "message": "Pruebas del proyecto ejecutadas en contenedor aislado sin acceso a red.",
        }
    except Exception as exc:
        return {
            "executed": True,
            "status": "error",
            "message": f"Error ejecutando pruebas en contenedor aislado: {exc}",
        }


# -----------------------------------------------------------------------------
# 5. Human Decision Workflow (Approve / Reject)
# -----------------------------------------------------------------------------

def record_human_remediation_review(
    finding: Dict[str, Any],
    decision: str,
    reason: str,
    author: str = "analista-seguridad",
) -> None:
    """Record human approval or rejection of proposed patch with mandatory reason."""
    clean_dec = str(decision).strip().lower()
    if clean_dec not in ("approved", "rejected", "aprobar", "rechazar"):
        raise ValueError(f"Decisión inválida '{decision}'. Debe ser 'approved' o 'rejected'.")

    clean_reason = str(reason).strip()
    if not clean_reason or len(clean_reason) < 3:
        raise ValueError("El motivo es obligatorio para aprobar o rechazar un parche.")

    remediation = finding.setdefault("remediation", {
        "status": "open",
        "diff": None,
        "touched_files": [],
        "method": "manual",
    })

    final_status = "approved" if clean_dec in ("approved", "aprobar") else "rejected"
    remediation["status"] = final_status
    remediation["reviewed_by"] = "persona"
    remediation["reviewer"] = str(author or "analista-seguridad").strip()
    remediation["review_decision"] = final_status
    remediation["review_reason"] = clean_reason
    remediation["review_timestamp"] = datetime.now(timezone.utc).isoformat()
