#!/usr/bin/env python3
"""
Helper script to clone and analyze repositories independently.
Used by the benchmark runner.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def clone_and_analyze(url: str, output_dir: str) -> dict:
    """Clone a repository and run analysis, saving results."""
    
    with tempfile.TemporaryDirectory(prefix="analyze-") as temp_dir:
        # Clone
        try:
            print(f"Cloning {url}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", url, temp_dir],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": f"Clone failed: {e}"}
        
        # Run semgrep
        try:
            print(f"Running Semgrep analysis...")
            result = subprocess.run(
                ["semgrep", "--config=p/owasp-top-ten", "--json", "--quiet", temp_dir],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            data = json.loads(result.stdout or "{}")
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": f"Analysis failed: {e}"}
        
        # Process results
        findings = []
        for raw in data.get("results", []):
            raw_path = str(raw.get("path", "Unknown"))
            path = os.path.relpath(raw_path, temp_dir)
            
            findings.append({
                "rule": raw.get("check_id", "unknown"),
                "file": path,
                "line": raw.get("start", {}).get("line"),
                "severity": raw.get("extra", {}).get("metadata", {}).get("severity", "medium"),
                "cwe": raw.get("extra", {}).get("metadata", {}).get("cwe", []),
            })
        
        return {
            "status": "completed",
            "findings": findings,
            "total": len(findings),
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: clone_and_analyze.py <url> [output_dir]")
        sys.exit(1)
    
    url = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    
    result = clone_and_analyze(url, output_dir)
    print(json.dumps(result, indent=2))
