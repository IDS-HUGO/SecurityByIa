#!/usr/bin/env python3
"""
Utilities for analyzing and reporting benchmark results.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class CategoryMetrics:
    """Metrics aggregated by category (CWE or OWASP)."""
    category: str
    total_gt: int
    detected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    recall: float
    precision: float
    f1_score: float


class ResultsAnalyzer:
    """Analyzes benchmark results and generates reports."""
    
    @staticmethod
    def load_results(results_file: str) -> Dict[str, Any]:
        """Load results from JSON file."""
        with open(results_file, 'r') as f:
            return json.load(f)
    
    @staticmethod
    def generate_csv_report(results: Dict[str, Any], output_file: str) -> None:
        """Generate CSV report of results."""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Repository ID',
                'Total GT',
                'TP',
                'FP',
                'FN',
                'Recall',
                'Precision',
                'F1 Score',
                'Timestamp',
            ])
            
            for repo in results.get('repositories', []):
                metrics = repo['metrics']
                writer.writerow([
                    repo['repo_id'],
                    metrics['total_findings'],
                    metrics['true_positives'],
                    metrics['false_positives'],
                    metrics['false_negatives'],
                    f"{metrics['recall']:.3f}",
                    f"{metrics['precision']:.3f}",
                    f"{metrics['f1_score']:.3f}",
                    repo['timestamp'],
                ])
    
    @staticmethod
    def generate_markdown_report(results: Dict[str, Any]) -> str:
        """Generate markdown report of results."""
        lines = [
            "# Benchmark Results",
            "",
            f"**Timestamp:** {results['timestamp']}",
            "",
        ]
        
        if results.get('summary'):
            lines.extend([
                "## Summary",
                "",
                f"- **Repositories Tested:** {results['summary']['total_repos']}",
                f"- **Average Recall:** {results['summary']['avg_recall']:.1%}",
                f"- **Average Precision:** {results['summary']['avg_precision']:.1%}",
                f"- **Average F1 Score:** {results['summary']['avg_f1_score']:.3f}",
                "",
            ])
        
        lines.extend([
            "## Per-Repository Results",
            "",
        ])
        
        for repo in results.get('repositories', []):
            metrics = repo['metrics']
            lines.extend([
                f"### {repo['repo_id']}",
                "",
                f"**Format:** {repo['repository']['format']}",
                "",
                "#### Metrics",
                "",
                f"- **Ground Truth Findings:** {metrics['total_findings']}",
                f"- **True Positives:** {metrics['true_positives']}",
                f"- **False Positives:** {metrics['false_positives']}",
                f"- **False Negatives:** {metrics['false_negatives']}",
                f"- **Recall (TPR):** {metrics['recall']:.1%}",
                f"- **Precision:** {metrics['precision']:.1%}",
                f"- **False Positive Rate:** {metrics['fpr']:.3f}",
                f"- **F1 Score:** {metrics['f1_score']:.3f}",
                "",
                "#### Analysis Metadata",
                "",
                "**Semgrep:**",
                f"- Version: `{repo['analysis_metadata']['semgrep']['version']}`",
                f"- Config: `{repo['analysis_metadata']['semgrep']['rules_config']}`",
                f"- Rules: {repo['analysis_metadata']['semgrep']['rule_count']}",
                "",
                "**Repository:**",
                f"- Commit: `{repo['analysis_metadata']['repository']['commit']}`",
                "",
            ])
        
        return "\n".join(lines)


def main():
    """CLI for analyzing results."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze benchmark results")
    parser.add_argument("--results", required=True, help="Path to results JSON file")
    parser.add_argument("--csv-output", help="Output CSV report")
    parser.add_argument("--markdown-output", help="Output Markdown report")
    
    args = parser.parse_args()
    
    analyzer = ResultsAnalyzer()
    results = analyzer.load_results(args.results)
    
    if args.csv_output:
        analyzer.generate_csv_report(results, args.csv_output)
        print(f"CSV report saved to {args.csv_output}")
    
    if args.markdown_output:
        report = analyzer.generate_markdown_report(results)
        with open(args.markdown_output, 'w') as f:
            f.write(report)
        print(f"Markdown report saved to {args.markdown_output}")
    
    # Print summary to stdout
    print("\nResults Summary:")
    print(json.dumps(results['summary'], indent=2))


if __name__ == "__main__":
    main()
