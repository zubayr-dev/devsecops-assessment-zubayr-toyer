# Multi-Scanner Security Orchestrator

Lightweight security aggregation tool designed to run SAST and secret detection in parallel, returning a unified JSON payload and exit codes suitable for CI/CD gates.

## Features
- **Unified Reporting:** Combines SAST and Secret findings into a standardized JSON structure.
- **Fail Thresholds:** Customizable `--fail-on` flag (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Graceful Fallbacks:** Uses system CLI tools (`bandit`, `gitleaks`) if available, falling back to built-in pattern matching when offline.

## Usage
```bash
# Run scan on target application folder
./scripts/multi-scanner/security-scan.py --path ./application --format json --fail-on HIGH