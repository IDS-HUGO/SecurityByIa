"""
Benchmark engine and management service for SAST security analyzer.
Clones or loads reference repositories, executes analyzer.analyze_directory,
matches findings against ground truth, aggregates CWE metrics, and tracks run deltas.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

import analyzer
import triage_agent

ROOT_DIR = Path(__file__).resolve().parent
BENCH_DIR = ROOT_DIR / "bench"
STORAGE_BENCH = ROOT_DIR / "storage" / "benchmark"
RUNS_DIR = STORAGE_BENCH / "runs"
BENCH_RESULTS_DIR = BENCH_DIR / "results"

STORAGE_BENCH.mkdir(parents=True, exist_ok=True)
RUNS_DIR.mkdir(parents=True, exist_ok=True)
BENCH_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

BASELINE_FILE = STORAGE_BENCH / "baseline.json"
LATEST_RUN_FILE = STORAGE_BENCH / "latest.json"
HISTORY_FILE = STORAGE_BENCH / "history.json"

# Concurrency state & lock
_bench_lock = threading.Lock()
_bench_state: Dict[str, Any] = {
    "is_running": False,
    "current_run_id": None,
    "feature": None,
    "status": "idle",
    "progress": 0,
    "stage": "idle",
    "message": "Sistema listo para ejecutar benchmark",
    "error": None,
    "start_time": None,
}

# Standard CWE Catalog for clear human-readable presentation
CWE_NAMES: Dict[str, Dict[str, str]] = {
    "CWE-78": {"name": "OS Command Injection", "category": "Injection"},
    "CWE-89": {"name": "SQL Injection", "category": "Injection"},
    "CWE-94": {"name": "Code Injection", "category": "Injection"},
    "CWE-95": {"name": "Eval Injection", "category": "Injection"},
    "CWE-327": {"name": "Broken Cryptographic Algorithm", "category": "Cryptography"},
    "CWE-798": {"name": "Hardcoded Credentials", "category": "Credentials & Secrets"},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "category": "Injection"},
    "CWE-22": {"name": "Path Traversal", "category": "Broken Access Control"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "Integrity Failures"},
    "CWE-287": {"name": "Improper Authentication", "category": "Authentication"},
    "CWE-200": {"name": "Information Exposure", "category": "Information Disclosure"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "category": "Access Control"},
}


@dataclass
class GroundTruthItem:
    file: str
    line: int
    rule_id: str
    cwe: str
    category: Optional[str] = None
    description: Optional[str] = None


def _clean_cwe(raw_cwe: Any) -> str:
    """Normalize CWE strings such as 'CWE-78: OS Command...' to 'CWE-78'."""
    if isinstance(raw_cwe, list):
        if not raw_cwe:
            return "CWE-Other"
        raw_cwe = raw_cwe[0]
    raw_str = str(raw_cwe or "").strip()
    match = re.search(r"CWE-\d+", raw_str, re.IGNORECASE)
    return match.group(0).upper() if match else "CWE-Other"


def detect_git_feature() -> str:
    """Auto-detect current commit or branch feature for benchmark labeling."""
    try:
        commit_msg = subprocess.run(
            ["git", "log", "-1", "--pretty=format:%s (%h)"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
        if commit_msg:
            return commit_msg
    except Exception:
        pass
    return "Motor de Análisis SAST con Reglas OWASP Top 10 + Secrets"


def get_semgrep_version() -> str:
    """Versión de Semgrep usada por el motor ('unknown' si no está disponible)."""
    try:
        semgrep_bin = analyzer._find_semgrep_bin() or "semgrep"
        result = subprocess.run(
            [str(semgrep_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        return output.splitlines()[0].strip() if output else "unknown"
    except Exception:
        return "unknown"


def get_rules_metadata() -> Dict[str, Any]:
    """Describe las reglas activas del motor: archivo local (ids + CWE) y configs del registry."""
    rules_file = ROOT_DIR / "rules" / "security-rules.yml"
    local_rules: List[Dict[str, Any]] = []
    if rules_file.exists():
        try:
            data = yaml.safe_load(rules_file.read_text(encoding="utf-8")) or {}
            for rule in data.get("rules", []):
                rule_id = rule.get("id")
                if not rule_id:
                    continue
                local_rules.append({
                    "id": rule_id,
                    "cwe": _clean_cwe(rule.get("metadata", {}).get("cwe")),
                })
        except Exception as exc:
            print(f"Error leyendo reglas locales {rules_file}: {exc}")
    return {
        "local_rules_file": "rules/security-rules.yml",
        "local_rules_loaded": bool(local_rules),
        "local_rule_ids": local_rules,
        "registry_configs": ["p/owasp-top-ten"],
    }


def get_git_commit(repo_path: Path) -> Optional[str]:
    """Commit HEAD de un repositorio (None si la ruta no es un repositorio git)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        commit = result.stdout.strip()
        return commit if commit else None
    except Exception:
        return None


def load_references(refs_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = refs_file or (BENCH_DIR / "refs.yml")
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("repositories", [])
    except Exception as exc:
        print(f"Error loading refs.yml: {exc}")
        return []


def parse_ground_truth(repo_path: Path, repo_format: str) -> List[GroundTruthItem]:
    findings: List[GroundTruthItem] = []
    if repo_format in ("vuln-markers", "example", "owasp"):
        candidates = [
            repo_path / "data" / "static" / "vulnerabilities.json",
            repo_path / "vulnerabilities.json",
            repo_path / "data" / "vulnerabilities.json",
        ]
        vuln_file = next((f for f in candidates if f.exists()), None)
        if not vuln_file:
            return findings

        try:
            with open(vuln_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                snippet = item.get("vuln_code_snippet", "") or item.get("file", "")
                line = item.get("vuln_line", item.get("line", 1))
                try:
                    line_num = int(line)
                except (ValueError, TypeError):
                    line_num = 1
                cwe_norm = _clean_cwe(item.get("cwe"))
                findings.append(
                    GroundTruthItem(
                        file=str(snippet).strip(),
                        line=line_num,
                        rule_id=item.get("name", "Vulnerability"),
                        cwe=cwe_norm,
                        category=item.get("category", "Security"),
                        description=item.get("name", "Vulnerability marker"),
                    )
                )
        except Exception as exc:
            print(f"Error reading ground truth at {vuln_file}: {exc}")

    elif repo_format == "csv-expected-results":
        csv_files = list(repo_path.rglob("expectedresults-0.1.csv"))
        if csv_files:
            import csv
            try:
                with open(csv_files[0], "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        test_num = row.get("TestCaseNumber", "").strip()
                        cwe = _clean_cwe(row.get("CWE", ""))
                        res = row.get("Result", "").strip()
                        if res in ("1", "true", "True", "TRUE") and test_num:
                            findings.append(
                                GroundTruthItem(
                                    file=f"src/test_{test_num}.py",
                                    line=1,
                                    rule_id=f"testcase-{test_num}",
                                    cwe=cwe,
                                    category=None,
                                )
                            )
            except Exception as exc:
                print(f"Error reading CSV ground truth: {exc}")

    return findings


def resolve_or_clone_repo(repo_ref: Dict[str, Any], temp_base: Path) -> Optional[Path]:
    """Resolve a repository: local path copy or shallow git clone."""
    url = repo_ref.get("url", "")
    repo_id = repo_ref.get("id", "repo")
    target_path = temp_base / repo_id

    if target_path.exists():
        shutil.rmtree(target_path, ignore_errors=True)

    # 1. Local relative or absolute path
    clean_url = url.replace("file://", "")
    local_candidates = [
        ROOT_DIR / clean_url,
        BENCH_DIR / clean_url,
        Path(clean_url),
    ]
    for cand in local_candidates:
        if cand.exists() and cand.is_dir():
            shutil.copytree(cand, target_path)
            return target_path

    # 2. Remote git clone
    if url.startswith("http://") or url.startswith("https://") or url.startswith("git@"):
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target_path)],
                check=True,
                capture_output=True,
                timeout=25,
            )
            return target_path
        except Exception as exc:
            print(f"Could not clone {url}: {exc}")
            return None

    return None


def match_findings(
    ground_truth: List[GroundTruthItem],
    detected_findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[GroundTruthItem], int, int, int]:
    """
    Match detected findings against ground truth.
    Returns (matched_detected, unmatched_gt, tp, fp, fn).
    """
    matched_detected = []
    used_gt: Set[int] = set()

    for det in detected_findings:
        det_file = Path(det.get("file", "")).name.lower()
        det_line = det.get("line") or 0
        det_cwe = _clean_cwe(det.get("cwe"))

        best_match_idx = None
        best_score = 0.0

        for idx, gt in enumerate(ground_truth):
            if idx in used_gt:
                continue

            gt_file = Path(gt.file).name.lower()
            file_matches = (det_file == gt_file) or (not det_file) or (not gt_file)
            cwe_matches = (det_cwe == gt.cwe) and (det_cwe != "CWE-OTHER")

            line_diff = abs(det_line - gt.line)
            line_close = line_diff <= 3

            score = 0.0
            if file_matches and line_close:
                score = 1.0 - (line_diff / 10.0)
            elif file_matches and cwe_matches:
                score = 0.75
            elif cwe_matches and line_close:
                score = 0.70

            if score > best_score:
                best_score = score
                best_match_idx = idx

        if best_match_idx is not None and best_score >= 0.6:
            used_gt.add(best_match_idx)
            gt_item = ground_truth[best_match_idx]
            matched_detected.append({
                **det,
                "matched": True,
                "match_score": round(best_score, 2),
                "gt_cwe": gt_item.cwe,
                "gt_line": gt_item.line,
                "gt_rule": gt_item.rule_id,
            })
        else:
            matched_detected.append({
                **det,
                "matched": False,
                "match_score": 0.0,
                "gt_cwe": None,
                "gt_line": None,
                "gt_rule": None,
            })

    unmatched_gt = [gt for idx, gt in enumerate(ground_truth) if idx not in used_gt]

    tp = sum(1 for m in matched_detected if m["matched"])
    fp = sum(1 for m in matched_detected if not m["matched"])
    fn = len(unmatched_gt)

    return matched_detected, unmatched_gt, tp, fp, fn


def calculate_metrics_dict(tp: int, fp: int, fn: int) -> Dict[str, float]:
    total_gt = tp + fn
    total_detected = tp + fp

    recall = round(tp / total_gt, 3) if total_gt > 0 else 0.0
    precision = round(tp / total_detected, 3) if total_detected > 0 else 0.0
    tpr = recall

    # FPR calibrated against total detections or known false alarms
    fpr = round(fp / max(1, total_detected), 3) if total_detected > 0 else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 3) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "total_ground_truth": total_gt,
        "total_detected": total_detected,
        "recall": recall,
        "tpr": tpr,
        "fpr": fpr,
        "precision": precision,
        "f1_score": f1,
    }


def compare_metrics(current: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute difference in percentage points (pts) between two metric sets."""
    if not previous:
        return {
            "has_previous": False,
            "delta_recall_pts": 0.0,
            "delta_tpr_pts": 0.0,
            "delta_fpr_pts": 0.0,
            "delta_precision_pts": 0.0,
            "delta_f1_pts": 0.0,
        }

    c_rec = float(current.get("recall", current.get("avg_recall", 0.0)))
    p_rec = float(previous.get("recall", previous.get("avg_recall", 0.0)))

    c_tpr = float(current.get("tpr", current.get("avg_tpr", c_rec)))
    p_tpr = float(previous.get("tpr", previous.get("avg_tpr", p_rec)))

    c_fpr = float(current.get("fpr", current.get("avg_fpr", 0.0)))
    p_fpr = float(previous.get("fpr", previous.get("avg_fpr", 0.0)))

    c_prec = float(current.get("precision", current.get("avg_precision", 0.0)))
    p_prec = float(previous.get("precision", previous.get("avg_precision", 0.0)))

    c_f1 = float(current.get("f1_score", current.get("avg_f1_score", 0.0)))
    p_f1 = float(previous.get("f1_score", previous.get("avg_f1_score", 0.0)))

    return {
        "has_previous": True,
        "delta_recall_pts": round((c_rec - p_rec) * 100, 1),
        "delta_tpr_pts": round((c_tpr - p_tpr) * 100, 1),
        "delta_fpr_pts": round((c_fpr - p_fpr) * 100, 1),
        "delta_precision_pts": round((c_prec - p_prec) * 100, 1),
        "delta_f1_pts": round((c_f1 - p_f1) * 100, 1),
    }


def aggregate_cwe_table(
    repos_results: List[Dict[str, Any]],
    previous_cwes: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Aggregate Ground Truth vs Detections by CWE Category across repositories."""
    cwe_map: Dict[str, Dict[str, Any]] = {}

    for repo in repos_results:
        # 1. Count Ground Truth per CWE
        for gt in repo.get("raw_ground_truth", []):
            cwe = _clean_cwe(gt.get("cwe"))
            if cwe not in cwe_map:
                info = CWE_NAMES.get(cwe, {"name": f"Categoría de Vulnerabilidad {cwe}", "category": "General"})
                cwe_map[cwe] = {
                    "cwe": cwe,
                    "name": info["name"],
                    "category": info["category"],
                    "total_gt": 0,
                    "detected": 0,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                }
            cwe_map[cwe]["total_gt"] += 1

        # 2. Count Detections & Matches per CWE
        for det in repo.get("raw_detected", []):
            cwe = _clean_cwe(det.get("gt_cwe") or det.get("cwe"))
            if cwe not in cwe_map:
                info = CWE_NAMES.get(cwe, {"name": f"Categoría de Vulnerabilidad {cwe}", "category": "General"})
                cwe_map[cwe] = {
                    "cwe": cwe,
                    "name": info["name"],
                    "category": info["category"],
                    "total_gt": 0,
                    "detected": 0,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                }
            cwe_map[cwe]["detected"] += 1
            if det.get("matched"):
                cwe_map[cwe]["tp"] += 1
            else:
                cwe_map[cwe]["fp"] += 1

    # 3. Calculate FN, Recall, Precision, FPR, and points delta for each CWE
    results: List[Dict[str, Any]] = []
    prev_by_cwe = previous_cwes or {}

    for cwe, stats in sorted(cwe_map.items()):
        total_gt = stats["total_gt"]
        tp = stats["tp"]
        fp = stats["fp"]
        fn = max(0, total_gt - tp)
        stats["fn"] = fn

        rec = round(tp / total_gt, 3) if total_gt > 0 else (1.0 if stats["detected"] > 0 else 0.0)
        prec = round(tp / stats["detected"], 3) if stats["detected"] > 0 else 0.0
        fpr = round(fp / max(1, stats["detected"]), 3)
        f1 = round((2 * prec * rec) / (prec + rec), 3) if (prec + rec) > 0 else 0.0

        metric_dict = {
            "recall": rec,
            "tpr": rec,
            "fpr": fpr,
            "precision": prec,
            "f1_score": f1,
        }
        prev_metric = prev_by_cwe.get(cwe)
        diff = compare_metrics(metric_dict, prev_metric)

        results.append({
            "cwe": cwe,
            "name": stats["name"],
            "category": stats["category"],
            "total_gt": total_gt,
            "detected": stats["detected"],
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "recall": rec,
            "tpr": rec,
            "fpr": fpr,
            "precision": prec,
            "f1_score": f1,
            "comparison": diff,
            "delta_recall_pts": diff["delta_recall_pts"],
            "delta_fpr_pts": diff["delta_fpr_pts"],
        })

    return results


def get_baseline() -> Optional[Dict[str, Any]]:
    for target in (BASELINE_FILE, BENCH_RESULTS_DIR / "baseline.json"):
        if target.exists():
            try:
                return json.loads(target.read_text(encoding="utf-8"))
            except Exception:
                pass
    return None


def get_latest_run() -> Optional[Dict[str, Any]]:
    if LATEST_RUN_FILE.exists():
        try:
            return json.loads(LATEST_RUN_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    # Fallback to most recent in runs directory
    all_runs = sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if all_runs:
        try:
            return json.loads(all_runs[0].read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def get_history() -> List[Dict[str, Any]]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _save_run_result(run_data: Dict[str, Any], save_as_baseline: bool = False) -> None:
    run_id = run_data["run_id"]

    # 1. Save specific run
    run_path = RUNS_DIR / f"{run_id}.json"
    content = json.dumps(run_data, ensure_ascii=False, indent=2)
    run_path.write_text(content, encoding="utf-8")

    # Also sync to bench/results
    (BENCH_RESULTS_DIR / f"{run_id}.json").write_text(content, encoding="utf-8")
    (BENCH_RESULTS_DIR / "benchmark-results.json").write_text(content, encoding="utf-8")

    # 2. Update latest
    LATEST_RUN_FILE.write_text(content, encoding="utf-8")

    # 3. Check baseline
    if not BASELINE_FILE.exists() or save_as_baseline:
        BASELINE_FILE.write_text(content, encoding="utf-8")
        (BENCH_RESULTS_DIR / "baseline.json").write_text(content, encoding="utf-8")

    # 4. Append to history index
    history = get_history()
    history_entry = {
        "run_id": run_id,
        "timestamp": run_data["timestamp"],
        "date_formatted": run_data["date_formatted"],
        "feature": run_data["feature"],
        "summary": run_data["summary"],
        "is_baseline": run_data.get("is_baseline", False),
    }
    history = [history_entry] + [h for h in history if h.get("run_id") != run_id][:30]
    HISTORY_FILE.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")


def get_benchmark_status() -> Dict[str, Any]:
    with _bench_lock:
        state = dict(_bench_state)
    latest = get_latest_run()
    baseline = get_baseline()
    refs = load_references()

    return {
        "status": state["status"],
        "is_running": state["is_running"],
        "progress": state["progress"],
        "stage": state["stage"],
        "message": state["message"],
        "error": state["error"],
        "current_run_id": state["current_run_id"],
        "latest_run": latest,
        "baseline": baseline,
        "reference_repos_count": len(refs),
        "history": get_history()[:10],
    }

def evaluate_tools_and_pairs(repos_results: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Calculate Recall, Precision, TP, FP, FN for each individual scanner tool
    and for each scanner pair across benchmark reference repositories.
    """
    distinct_tools = set()
    for r in repos_results:
        for det in r.get("raw_detected", []):
            for t in (det.get("tools") or []):
                distinct_tools.add(str(t))

    sorted_tools = sorted(distinct_tools)
    tool_evals = []

    # Single tool evaluations
    for t in sorted_tools:
        total_tp = 0
        total_fp = 0
        total_fn = 0
        total_gt = 0
        total_det = 0

        for r in repos_results:
            gt_items = [
                GroundTruthItem(
                    file=item.get("file", ""),
                    line=int(item.get("line") or 1),
                    rule_id=str(item.get("rule_id", "")),
                    cwe=str(item.get("cwe", "CWE-Other")),
                    category=item.get("category"),
                )
                for item in r.get("raw_ground_truth", [])
            ]
            t_findings = [f for f in r.get("raw_detected", []) if t in (f.get("tools") or [])]
            _, _, tp, fp, fn = match_findings(gt_items, t_findings)
            total_tp += tp
            total_fp += fp
            total_fn += fn
            total_gt += len(gt_items)
            total_det += len(t_findings)

        rec = round(total_tp / total_gt, 3) if total_gt > 0 else 0.0
        prec = round(total_tp / total_det, 3) if total_det > 0 else 0.0
        fpr = round(total_fp / max(1, total_det), 3) if total_det > 0 else 0.0

        tool_evals.append({
            "tool": t,
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "total_detected": total_det,
            "total_ground_truth": total_gt,
            "recall": rec,
            "tpr": rec,
            "precision": prec,
            "fpr": fpr,
        })

    tool_evals.sort(key=lambda x: (x["recall"], x["precision"]), reverse=True)

    # Scanner pairs evaluations
    pairs_evals = []
    for i in range(len(sorted_tools)):
        for j in range(i + 1, len(sorted_tools)):
            t1, t2 = sorted_tools[i], sorted_tools[j]
            total_tp = 0
            total_fp = 0
            total_fn = 0
            total_gt = 0
            total_det = 0

            for r in repos_results:
                gt_items = [
                    GroundTruthItem(
                        file=item.get("file", ""),
                        line=int(item.get("line") or 1),
                        rule_id=str(item.get("rule_id", "")),
                        cwe=str(item.get("cwe", "CWE-Other")),
                        category=item.get("category"),
                    )
                    for item in r.get("raw_ground_truth", [])
                ]
                pair_findings = [
                    f for f in r.get("raw_detected", [])
                    if t1 in (f.get("tools") or []) or t2 in (f.get("tools") or [])
                ]
                _, _, tp, fp, fn = match_findings(gt_items, pair_findings)
                total_tp += tp
                total_fp += fp
                total_fn += fn
                total_gt += len(gt_items)
                total_det += len(pair_findings)

            rec = round(total_tp / total_gt, 3) if total_gt > 0 else 0.0
            prec = round(total_tp / total_det, 3) if total_det > 0 else 0.0
            fpr = round(total_fp / max(1, total_det), 3) if total_det > 0 else 0.0

            pairs_evals.append({
                "tools": [t1, t2],
                "pair_label": f"{t1} + {t2}",
                "true_positives": total_tp,
                "false_positives": total_fp,
                "false_negatives": total_fn,
                "total_detected": total_det,
                "total_ground_truth": total_gt,
                "recall": rec,
                "tpr": rec,
                "precision": prec,
                "fpr": fpr,
            })

    pairs_evals.sort(key=lambda x: (x["recall"], x["precision"]), reverse=True)
    return tool_evals, pairs_evals


def execute_benchmark_task(
    feature_name: Optional[str] = None,
    save_as_baseline: bool = False,
    existing_run_id: Optional[str] = None,
    repo_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Execute complete benchmark run reusing analyzer.analyze_directory."""
    with _bench_lock:
        if _bench_state["is_running"] and _bench_state["current_run_id"] != existing_run_id:
            raise RuntimeError("Ya hay una corrida de benchmark en ejecución.")

        run_id = existing_run_id or f"bench_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        now_utc = datetime.now(timezone.utc)
        feature = (feature_name or "").strip() or detect_git_feature()

        _bench_state.update({
            "is_running": True,
            "current_run_id": run_id,
            "feature": feature,
            "status": "running",
            "progress": 5,
            "stage": "initializing",
            "message": "Inicializando suite de benchmark...",
            "error": None,
            "start_time": now_utc.isoformat(),
        })

    temp_repos_dir = Path("/tmp/bench-repos-run") / run_id
    temp_repos_dir.mkdir(parents=True, exist_ok=True)

    previous_run = get_latest_run()
    previous_cwes_map = {item["cwe"]: item for item in (previous_run.get("cwe_categories", []) if previous_run else [])}
    previous_repos_map = {r["id"]: r for r in (previous_run.get("repositories", []) if previous_run else [])}

    try:
        refs = load_references()
        if repo_ids:
            wanted = {str(rid) for rid in repo_ids}
            refs = [ref for ref in refs if ref.get("id") in wanted]
        if not refs:
            raise RuntimeError("No se encontraron repositorios de referencia en bench/refs.yml")

        # Prioritize local reference repos if network repos fail or time out
        repos_results = []
        total_refs = len(refs)

        for idx, ref in enumerate(refs, start=1):
            repo_id = ref.get("id")
            repo_name = ref.get("name", repo_id)
            repo_format = ref.get("format", "vuln-markers")

            pct = int(10 + (idx / total_refs) * 75)
            with _bench_lock:
                _bench_state.update({
                    "progress": pct,
                    "stage": f"analyzing_{repo_id}",
                    "message": f"Analizando {repo_name} ({idx}/{total_refs})...",
                })

            # 1. Resolve or clone
            repo_local_path = resolve_or_clone_repo(ref, temp_repos_dir)
            if not repo_local_path or not repo_local_path.exists():
                print(f"Skipping repo {repo_id}: unable to resolve or clone.")
                continue

            # Commit evaluado de la referencia (None para copias locales sin .git).
            repo_commit = get_git_commit(repo_local_path)

            # Corrida de humo sin ground truth por codigo (no inventa TPR/FPR).
            if repo_format == "fpr-smoke":
                try:
                    smoke_result = analyzer.analyze_directory(
                        str(repo_local_path),
                        repo_url=ref.get("url", f"local://{repo_id}"),
                        enable_ai=False,
                    )
                    smoke_findings = smoke_result.get("findings", [])
                    smoke_error = None
                except Exception as exc:
                    smoke_findings = []
                    smoke_error = str(exc)
                repos_results.append({
                    "id": repo_id,
                    "name": repo_name,
                    "type": ref.get("type", "general"),
                    "format": "fpr-smoke",
                    "description": ref.get("description", ""),
                    "commit": repo_commit,
                    "metrics": {
                        "smoke": True,
                        "total_detected": len(smoke_findings),
                        **({"error": smoke_error} if smoke_error else {}),
                        "note": ("Corrida de humo de FPR: el repositorio no publica "
                                 "ground truth por código; no se calculan TPR/FPR."),
                    },
                    "comparison": {},
                    "findings_detected": len(smoke_findings),
                    "ground_truth_count": 0,
                    "raw_ground_truth": [],
                    "raw_detected": [],
                    "sample_findings": [
                        {"rule": f.get("rule"), "file": f.get("file"),
                         "line": f.get("line"), "severity": f.get("severity"),
                         "cwe": f.get("cwe")}
                        for f in smoke_findings[:15]
                    ],
                })
                continue

            # 2. Parse Ground Truth
            gt_items = parse_ground_truth(repo_local_path, repo_format)

            # 3. Reutilizar el motor de análisis de analyzer.py!
            scan_result = analyzer.analyze_directory(
                str(repo_local_path),
                repo_url=ref.get("url", f"local://{repo_id}"),
                enable_ai=False,
            )
            detected_findings = scan_result.get("findings", [])

            # 4. Match findings
            matched_detected, unmatched_gt, tp, fp, fn = match_findings(gt_items, detected_findings)
            metrics = calculate_metrics_dict(tp, fp, fn)

            # 5. Compare with previous run for this repo
            prev_repo = previous_repos_map.get(repo_id)
            repo_comparison = compare_metrics(metrics, prev_repo.get("metrics") if prev_repo else None)

            repos_results.append({
                "id": repo_id,
                "name": repo_name,
                "type": ref.get("type", "general"),
                "format": repo_format,
                "description": ref.get("description", ""),
                "commit": repo_commit,
                "metrics": metrics,
                "comparison": repo_comparison,
                "findings_detected": len(detected_findings),
                "ground_truth_count": len(gt_items),
                "raw_ground_truth": [asdict(item) for item in gt_items],
                "raw_detected": matched_detected,
                "sample_findings": matched_detected[:10],
            })

        if not repos_results:
            raise RuntimeError("No fue posible analizar ninguno de los repositorios de referencia.")

        with _bench_lock:
            _bench_state.update({
                "progress": 90,
                "stage": "aggregating",
                "message": "Calculando métricas CWE y comparativas...",
            })

        # Calculate overall averages (solo repos con métricas reales; los smoke no entran)
        measured = [r for r in repos_results if not r["metrics"].get("smoke")]
        if not measured and not repos_results:
            raise RuntimeError("Ningún repositorio de referencia produjo métricas medibles.")
        total_repos = max(1, len(measured))
        tot_gt = sum(r["metrics"]["total_ground_truth"] for r in measured)
        tot_det = sum(r["metrics"]["total_detected"] for r in measured)
        tot_tp = sum(r["metrics"]["true_positives"] for r in measured)
        tot_fp = sum(r["metrics"]["false_positives"] for r in measured)
        tot_fn = sum(r["metrics"]["false_negatives"] for r in measured)

        if measured:
            avg_recall = round(sum(r["metrics"]["recall"] for r in measured) / total_repos, 3)
            avg_tpr = avg_recall
            avg_fpr = round(sum(r["metrics"]["fpr"] for r in measured) / total_repos, 3)
            avg_prec = round(sum(r["metrics"]["precision"] for r in measured) / total_repos, 3)
            avg_f1 = round(sum(r["metrics"]["f1_score"] for r in measured) / total_repos, 3)
        else:
            avg_recall = avg_tpr = avg_fpr = avg_prec = avg_f1 = 0.0

        summary = {
            "total_repos": total_repos,
            "total_ground_truth": tot_gt,
            "total_detected": tot_det,
            "true_positives": tot_tp,
            "false_positives": tot_fp,
            "false_negatives": tot_fn,
            "avg_recall": avg_recall,
            "avg_tpr": avg_tpr,
            "avg_fpr": avg_fpr,
            "avg_precision": avg_prec,
            "avg_f1_score": avg_f1,
        }

        # Overall comparison in points
        global_comparison = compare_metrics(summary, previous_run.get("summary") if previous_run else None)

        # Baseline comparison in points
        baseline_obj = get_baseline()
        baseline_comparison = compare_metrics(summary, baseline_obj.get("summary") if baseline_obj else None)

        # CWE categories breakdown table
        cwe_categories = aggregate_cwe_table(repos_results, previous_cwes_map)

        # Clean sanitized repos list for JSON stability
        clean_repositories = []
        for r in repos_results:
            clean_repositories.append({
                "id": r["id"],
                "name": r["name"],
                "type": r["type"],
                "format": r["format"],
                "description": r["description"],
                "commit": r.get("commit"),
                "metrics": r["metrics"],
                "comparison": r["comparison"],
                "findings_detected": r["findings_detected"],
                "ground_truth_count": r["ground_truth_count"],
                "sample_findings": r["sample_findings"],
            })

        # Tool & Scanner Pairs breakdown evaluations
        tool_evaluations, scanner_pairs = evaluate_tools_and_pairs(repos_results)

        # Multi-model AI triage FPR comparison (Gemini vs OpenAI vs Claude)
        all_detected_findings = []
        for r in repos_results:
            all_detected_findings.extend(r.get("raw_detected", []))
        triage_benchmark = triage_agent.evaluate_multi_model_triage_benchmark(
            all_detected_findings,
            raw_fpr=avg_fpr,
        )

        duration = round((datetime.now(timezone.utc) - now_utc).total_seconds(), 2)

        run_output: Dict[str, Any] = {
            "run_id": run_id,
            "timestamp": now_utc.isoformat(),
            "date_formatted": now_utc.strftime("%d %b %Y, %H:%M:%S UTC"),
            "feature": feature,
            "is_baseline": save_as_baseline or (baseline_obj is None),
            "duration_seconds": duration,
            "metadata": {
                "semgrep_version": get_semgrep_version(),
                "rules": get_rules_metadata(),
                "tool_commit": get_git_commit(ROOT_DIR),
            },
            "summary": summary,
            "comparison": {
                **global_comparison,
                "previous_run_id": previous_run.get("run_id") if previous_run else None,
                "previous_timestamp": previous_run.get("timestamp") if previous_run else None,
                "previous_feature": previous_run.get("feature") if previous_run else None,
            },
            "baseline_comparison": {
                **baseline_comparison,
                "baseline_timestamp": baseline_obj.get("timestamp") if baseline_obj else None,
                "baseline_feature": baseline_obj.get("feature") if baseline_obj else None,
            },
            "repositories": clean_repositories,
            "cwe_categories": cwe_categories,
            "tool_evaluations": tool_evaluations,
            "scanner_pairs": scanner_pairs,
            "triage_benchmark": triage_benchmark,
        }

        _save_run_result(run_output, save_as_baseline=save_as_baseline)

        with _bench_lock:
            _bench_state.update({
                "is_running": False,
                "status": "completed",
                "progress": 100,
                "stage": "completed",
                "message": f"Corrida de benchmark {run_id} finalizada exitosamente.",
                "error": None,
            })

        return run_output

    except Exception as exc:
        error_msg = str(exc)
        with _bench_lock:
            _bench_state.update({
                "is_running": False,
                "status": "error",
                "progress": 100,
                "stage": "failed",
                "message": "La corrida de benchmark falló",
                "error": error_msg,
            })
        raise
    finally:
        shutil.rmtree(temp_repos_dir, ignore_errors=True)


def start_benchmark_run_async(
    feature_name: Optional[str] = None,
    save_as_baseline: bool = False,
) -> Dict[str, Any]:
    """
    Launch a benchmark run in a background daemon thread, enforcing a single concurrent run.
    Returns immediate status dictionary with run_id and metadata.
    """
    with _bench_lock:
        if _bench_state["is_running"]:
            raise RuntimeError("Ya hay una corrida de benchmark en ejecución.")

        run_id = f"bench_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        now_utc = datetime.now(timezone.utc)
        feature = (feature_name or "").strip() or detect_git_feature()

        _bench_state.update({
            "is_running": True,
            "current_run_id": run_id,
            "feature": feature,
            "status": "running",
            "progress": 5,
            "stage": "initializing",
            "message": "Inicializando suite de benchmark...",
            "error": None,
            "start_time": now_utc.isoformat(),
        })

    def _worker():
        try:
            execute_benchmark_task(
                feature_name=feature,
                save_as_baseline=save_as_baseline,
                existing_run_id=run_id,
            )
        except Exception as exc:
            with _bench_lock:
                _bench_state.update({
                    "is_running": False,
                    "status": "error",
                    "progress": 100,
                    "stage": "failed",
                    "message": "La corrida de benchmark falló",
                    "error": str(exc),
                })

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    return {
        "status": "running",
        "run_id": run_id,
        "feature": feature,
        "is_baseline": save_as_baseline,
        "message": "Corrida de benchmark iniciada con éxito.",
        "started_at": now_utc.isoformat(),
    }
