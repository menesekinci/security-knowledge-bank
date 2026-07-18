---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "6. Prevention Checklist"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 8/11
---

## 6. Prevention Checklist

- [ ] **Use `sensitive = true` on all variables containing secrets** — prevents display in plan/apply output.
- [ ] **Never hardcode secrets in `.tf` files** — use environment variables, Vault, AWS Secrets Manager, or `.tfvars` files (gitignored).
- [ ] **Use `checkov`, `tfsec`, or `semgrep` as pre-commit hooks** — scan for hardcoded secrets, public S3, wildcard IAM, and missing encryption.
- [ ] **Enable S3 bucket public access blocking** — always include `aws_s3_bucket_public_access_block` with all four blocks enabled.
- [ ] **Encrypt state files** — set `encrypt = true` for S3 backends, use a KMS key.
- [ ] **Use DynamoDB for state locking** — prevents concurrent modifications and corruption.
- [ ] **Apply IAM least privilege** — no wildcard `Action: "*"` or `Resource: "*"`. Use specific resource ARNs and actions.
- [ ] **Encrypt all data at rest** — enable `storage_encrypted` on RDS, `encrypted = true` on EBS, SSE-S3/KMS on S3.
- [ ] **Use custom VPCs, not default** — default VPCs lack proper network segmentation.
- [ ] **Restrict security group ingress** — only expose necessary ports, never `0.0.0.0/0` for SSH or databases.
- [ ] **Enable S3 bucket versioning** — protects against accidental deletion or overwrite.
- [ ] **Tag all resources** — enable cost tracking, security audit, and resource identification.
- [ ] **Require IMDSv2** — set `metadata_options { http_tokens = "required" }` on EC2 instances.
- [ ] **Use `terraform plan -out=tfplan` and review before apply** — never auto-approve in production.
- [ ] **Pin provider versions** — specify `required_providers` with version constraints to avoid unexpected upgrades.
- [ ] **Enable S3 block public access at account level** — set `aws_s3_account_public_access_block` for organization-wide protection.
- [ ] **Rotate IAM keys regularly** — use `aws_iam_access_key` with resource-based rotation policies.
- [ ] **Use dedicated Terraform service accounts** — never use root/administrator credentials for Terraform.

---