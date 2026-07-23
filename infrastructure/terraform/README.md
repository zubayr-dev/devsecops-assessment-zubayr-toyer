# Infrastructure as Code (IaC) Security Baseline

This directory defines hardened cloud infrastructure modules using **Terraform**, paired with policy validation via **Checkov**.

## Implemented Security Controls

### 1. Storage Hardening (`aws_s3_bucket`)
- **Public Access Block:** `block_public_acls` and `restrict_public_buckets` set to `true`.
- **Encryption-at-Rest:** Mandatory AES-256 server-side encryption configuration.
- **Encryption-in-Transit:** S3 Bucket Policy explicitly denies non-HTTPS (`aws:SecureTransport = false`) requests.

### 2. Secret Management Approach
- **Zero Hardcoded Credentials:** Application secrets are declared using `sensitive = true` input variables and stored in **AWS Secrets Manager**.
- **Runtime Injection:** Passwords and tokens are injected via environment variables (`TF_VAR_db_password`) or CI secrets stores, avoiding plain-text exposure in version control or Terraform state logs.

### 3. Policy Enforcement & Scanning
Static analysis is executed on IaC manifests prior to deployment using **Checkov**:

```bash
# Run Checkov scanner locally
checkov -d infrastructure/terraform/ --config-file infrastructure/terraform/.checkov.yaml