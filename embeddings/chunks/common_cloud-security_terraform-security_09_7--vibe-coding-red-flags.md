---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "7. Vibe-Coding Red Flags (Terraform-Specific)"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 9/11
---

## 7. Vibe-Coding Red Flags (Terraform-Specific)

- [ ] **Hardcoded passwords in `main.tf`** — `password = "..."` or `secret_key = "..."` directly in resource blocks.
- [ ] **Wildcard IAM actions** — `Action = "*"` or `Action = ["s3:*"]` — overly permissive.
- [ ] **Wildcard IAM resources** — `Resource = "*"` — grants access to all resources.
- [ ] **`Principal = "*"` in bucket policies** — makes S3 bucket world-accessible.
- [ ] **`acl = "public-read"` or `acl = "public-read-write"`** — bucket is world-readable/writable.
- [ ] **No `aws_s3_bucket_public_access_block` resource** — missing public access controls.
- [ ] **`ingress` with `cidr_blocks = ["0.0.0.0/0"]` and port 22, 3306, 5432, or 6379** — SSH, MySQL, Postgres, Redis exposed to the world.
- [ ] **No `storage_encrypted` on RDS** — database data at rest is unencrypted.
- [ ] **No `encrypted = true` on EBS volumes** — disk data is unencrypted.
- [ ] **No `sensitive = true` on variable definitions** — secrets printed in logs.
- [ ] **Default value for password variables** — `default = "password123"` in `variables.tf`.
- [ ] **`terraform.tfvars` not in `.gitignore`** — secrets committed to version control.
- [ ] **No backend configuration** — state stored locally, easily lost or leaked.
- [ ] **Backend without `encrypt = true`** — state file at rest is plaintext.
- [ ] **Backend without DynamoDB locking** — concurrent runs can corrupt state.
- [ ] **`skip_final_snapshot = true`** — production DB destroyed without backup.
- [ ] **`publicly_accessible = true` on RDS** — database accessible from the internet.
- [ ] **`delete_protection = false`** (or absent) on critical resources — easy to accidentally destroy.
- [ ] **No `tags` block on resources** — untracked, ungoverned infrastructure.
- [ ] **`force_destroy = true` on S3 buckets** — destroys bucket even if it contains objects.
- [ ] **`count` or `for_each` used without explicit resource naming** — resources hard to track in console.
- [ ] **Provider credentials inline** — `access_key` and `secret_key` in provider block.
- [ ] **`terraform apply -auto-approve` in CI/CD** — no human review of infrastructure changes.
- [ ] **No version constraints for providers** — `version = "~> 4.0"` instead of `version = ">= 4.0, < 5.0"`.
- [ ] **Default VPC or `default_security_group` used** — no network isolation.
- [ ] **`lifecycle { prevent_destroy = true }` absent on critical resources** — allows accidental deletion.

---