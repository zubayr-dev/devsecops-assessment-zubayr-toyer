#!/usr/bin/env python3
"""
Multi-Scanner Security Orchestrator
Aggregates SAST and Secret Scanning tools with built-in native fallbacks.
"""

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


class SecurityOrchestrator:
    def __init__(self, target_path: str, fail_severity: str):
        self.target_path = Path(target_path).resolve()
        self.fail_severity = fail_severity.upper()
        self.results = {
            "status": "PASSED",
            "target": str(self.target_path),
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "scanners": {}
        }

    def _get_target_files(self):
        """Helper to get files whether target_path is a file or directory."""
        if self.target_path.is_file():
            return [self.target_path]
        elif self.target_path.is_dir():
            return [
                f for f in self.target_path.rglob("*")
                if f.is_file() and not any(part.startswith(".") for part in f.parts)
            ]
        return []

    def run_sast(self):
        """Runs Bandit SAST scanner, falling back to Python AST scanner if missing."""
        scanner_name = "bandit"
        if shutil.which(scanner_name):
            cmd = [scanner_name, "-r", str(self.target_path), "-f", "json", "-q"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            findings = []
            try:
                raw_data = json.loads(res.stdout) if res.stdout else {}
                for item in raw_data.get("results", []):
                    sev = item.get("issue_severity", "LOW").upper()
                    if sev in self.results["summary"]:
                        self.results["summary"][sev] += 1
                    findings.append({
                        "issue": item.get("issue_text"),
                        "severity": sev,
                        "file": item.get("filename"),
                        "line": item.get("line_number")
                    })
                self.results["scanners"][scanner_name] = {
                    "status": "COMPLETED",
                    "findings_count": len(findings),
                    "findings": findings
                }
                return
            except json.JSONDecodeError:
                pass

        # Fallback Native AST SAST Scanner for Python code
        self._fallback_sast_scan()

    def _fallback_sast_scan(self):
        """Native AST SAST scanner for detecting dangerous functions like eval(), exec(), shell=True."""
        findings = []
        for file_path in self._get_target_files():
            if file_path.suffix == ".py":
                try:
                    tree = ast.parse(file_path.read_text(errors="ignore"))
                    for node in ast.walk(tree):
                        # Detect eval() or exec()
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                            if node.func.id in ("eval", "exec"):
                                self.results["summary"]["HIGH"] += 1
                                findings.append({
                                    "issue": f"Use of dangerous function '{node.func.id}()'",
                                    "severity": "HIGH",
                                    "file": str(file_path),
                                    "line": node.lineno
                                })
                        # Detect subprocess with shell=True
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                            if node.func.attr in ("run", "Popen", "call"):
                                for kw in node.keywords:
                                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                        self.results["summary"]["HIGH"] += 1
                                        findings.append({
                                            "issue": "Subprocess execution with shell=True",
                                            "severity": "HIGH",
                                            "file": str(file_path),
                                            "line": node.lineno
                                        })
                except Exception:
                    continue

        self.results["scanners"]["sast_internal"] = {
            "status": "COMPLETED",
            "findings_count": len(findings),
            "findings": findings
        }

    def run_secret_scan(self):
        """Runs Gitleaks if available, otherwise falls back to broad regex secret matching."""
        scanner_name = "gitleaks"
        if shutil.which(scanner_name):
            cmd = [
                scanner_name, "detect",
                "--source", str(self.target_path),
                "--report-format", "json",
                "--report-path", "/tmp/gitleaks-results.json",
                "--no-git"
            ]
            subprocess.run(cmd, capture_output=True, text=True)
            report_file = Path("/tmp/gitleaks-results.json")
            
            findings = []
            if report_file.exists():
                try:
                    data = json.loads(report_file.read_text())
                    for item in data:
                        self.results["summary"]["HIGH"] += 1
                        findings.append({
                            "issue": f"Secret detected: {item.get('Description')}",
                            "severity": "HIGH",
                            "file": item.get("File"),
                            "line": item.get("StartLine")
                        })
                    report_file.unlink(missing_ok=True)
                    self.results["scanners"][scanner_name] = {
                        "status": "COMPLETED",
                        "findings_count": len(findings),
                        "findings": findings
                    }
                    return
                except json.JSONDecodeError:
                    pass

        # Fallback Secret Scanner
        self._fallback_secret_scan()

    def _fallback_secret_scan(self):
        """Broad secret scanner for AWS keys, tokens, and hardcoded credentials."""
        patterns = {
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "GitHub Token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
            "Hardcoded API Key/Secret": re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]")
        }
        
        findings = []
        for file_path in self._get_target_files():
            try:
                content = file_path.read_text(errors="ignore")
                for line_no, line in enumerate(content.splitlines(), start=1):
                    for label, pattern in patterns.items():
                        if pattern.search(line):
                            self.results["summary"]["CRITICAL"] += 1
                            findings.append({
                                "issue": f"Potential {label} detected",
                                "severity": "CRITICAL",
                                "file": str(file_path),
                                "line": line_no
                            })
            except Exception:
                continue

        self.results["scanners"]["secret_internal"] = {
            "status": "COMPLETED",
            "findings_count": len(findings),
            "findings": findings
        }

    def evaluate_pass_fail(self) -> int:
        """Determines exit code based on severity threshold."""
        thresholds = {
            "LOW": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "MEDIUM": ["MEDIUM", "HIGH", "CRITICAL"],
            "HIGH": ["HIGH", "CRITICAL"],
            "CRITICAL": ["CRITICAL"]
        }
        active_thresholds = thresholds.get(self.fail_severity, ["HIGH", "CRITICAL"])
        
        total_failing_issues = sum(
            self.results["summary"][sev] for sev in active_thresholds
        )

        if total_failing_issues > 0:
            self.results["status"] = "FAILED"
            return 1
        return 0


def main():
    parser = argparse.ArgumentParser(description="Multi-Scanner Security Orchestrator")
    parser.add_argument("--path", required=True, help="Path to target directory or file")
    parser.add_argument("--format", choices=["json", "summary"], default="json", help="Output format")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Severity threshold")

    args = parser.parse_args()

    orchestrator = SecurityOrchestrator(target_path=args.path, fail_severity=args.fail_on)
    orchestrator.run_sast()
    orchestrator.run_secret_scan()
    
    exit_code = orchestrator.evaluate_pass_fail()

    if args.format == "json":
        print(json.dumps(orchestrator.results, indent=2))
    else:
        print(f"--- Security Scan Status: {orchestrator.results['status']} ---")
        print(f"Summary: {json.dumps(orchestrator.results['summary'])}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()