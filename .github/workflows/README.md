# Secure Pipeline Architecture & Quality Gates

This GitHub Actions workflow implements automated "Shift Left" security verification on every push and pull request.

## Security Controls Integrated
1. **Gitleaks Secret Scanning:** Scans git commits for hardcoded API keys, certificates, and passwords.
2. **Semgrep SAST:** Scans application code for insecure programming patterns and vulnerability signatures.
3. **Custom Orchestrator (`security-scan.py`):** Runs local SAST and secret checks using custom organizational logic.

## Quality Gate Logic
- **Hard Gate (Fail):** 
  - Any detected **hardcoded secrets** immediately fail the build (`secret-detection` job).
  - Any **CRITICAL** or **HIGH** severity finding detected by the Custom Orchestrator exits with code `1` and blocks PR merge.
- **Soft Gate (Warn):**
  - **LOW** or **MEDIUM** findings emit step warnings (`::warning`) in the GitHub Actions summary tab without stopping the pipeline execution, allowing developer velocity while capturing technical debt.