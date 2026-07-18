# Terraform & OpenTofu IaC Security Deep Dive

> **Category:** Cloud Security / Infrastructure as Code  
> **Focus:** Hardcoded secrets, overly permissive IAM, public S3 buckets, default VPC, state file exposure, missing encryption, insecure state backends  
> **Severity:** High  
> **CWE:** CWE-312 (Cleartext Storage of Sensitive Info), CWE-200 (Info Exposure), CWE-284 (Access Control), CWE-319 (Cleartext Transmission), CWE-332 (Weak PRNG), CWE-532 (Info Exposure via Logs)  
> **AI Generation Risk:** High  
> **Last Updated:** July 2026

---

## Overview

Terraform and OpenTofu are the dominant Infrastructure as Code (IaC) tools, and AI code generators are routinely tasked with generating Terraform configurations for AWS, Azure, GCP, and other providers. The AI-generated patterns are especially dangerous because they create infrastructure that:

1. Is **persistent** and **cost-incurring** (not easily thrown away like buggy code)
2. Often has **public network exposure** (S3 buckets, security groups, load balancers)
3. **Stores secrets in state files** that are frequently stored in S3/GCS buckets or local files
4. **Lacks audit trails** — no logging, no tagging, no monitoring

The Terraform ecosystem has seen CVEs in the AWS provider (weak IAM password generation), cleartext state transmission (Azure backend), Terraform Enterprise (auth bypass, 2FA bypass, log leakage), and GitLab's Terraform API (state overwrite).

---

## 1. Vulnerability Explanation — AI-Generated Terraform Risks

### 1.1 Hardcoded Secrets in `.tf` Files

AI models frequently embed secrets directly in Terraform files — database passwords, API keys, access/secret keys — because the prompt asks for a "self-contained" or "complete" configuration. This is the most common and most dangerous AI-generated IaC vulnerability.

```hcl
# 💀 VULNERABLE — Hardcoded secrets in main.tf
resource "aws_db_instance" "main" {
  username = "admin"
  password = "SuperSecret123!"  # In plain text, committed to git
}

provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"   # 💀 Leaked if committed
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 💀
}
```

### 1.2 Overly Permissive IAM Policies

AI-generated IAM policies tend to use wildcards for both resource ARNs and actions. This is the IaC equivalent of `chmod 777`:

```hcl
# 💀 VULNERABLE — Wildcard IAM policy
resource "aws_iam_role_policy" "lambda_policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"      # All actions
        Resource = "*"      # All resources
      }
    ]
  })
}
```

### 1.3 Public S3 Buckets / Unrestricted Access

AI models are trained on examples that enable static website hosting via public S3 buckets. The result is data exposure:

```hcl
# 💀 VULNERABLE — Public S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-123"
  acl    = "public-read"  # 💀 World-readable
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  # Missing — AI completely omitted this resource
}
```

### 1.4 Default VPC Usage

AI models often use the default VPC, which lacks proper network isolation:

```hcl
# 💀 VULNERABLE — Using default VPC
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  # No vpc_security_group_ids — uses default VPC's default SG
  # No subnet_id — uses default subnet
}
```

### 1.5 No Encryption on Data Resources

AI frequently omits encryption settings on S3 buckets, EBS volumes, RDS instances, and DynamoDB tables:

```hcl
# 💀 VULNERABLE — No encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data"
  # No server_side_encryption_configuration
}

resource "aws_ebs_volume" "data" {
  size = 100
  # No encrypted = true
}
```

### 1.6 Remote State Without Encryption

AI-generated Terraform backends frequently omit state file encryption and access controls:

```hcl
# 💀 VULNERABLE — State backend without encryption
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    # No encrypt = true
    # No kms_key_id
    # No dynamodb_table for state locking
  }
}
```

### 1.7 Missing Resource Tags

AI models often omit tags, making cost allocation, security incident response, and resource identification impossible:

```hcl
# 💀 VULNERABLE — No tags
resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.medium"
  # No tags block — untracked resource
}
```

---

## 2. How AI Generates These Vulnerabilities

| Vulnerability Pattern | AI Prompt That Triggers It |
|---|---|
| Hardcoded secrets | "Create a complete Terraform config for an RDS instance" |
| Wildcard IAM | "Give the Lambda function full access" |
| Public S3 bucket | "Create a static website with S3" |
| Default VPC | "Deploy an EC2 instance in AWS" (with no VPC/subnet specified) |
| Missing encryption | "Create an S3 bucket for file storage" |
| Insecure state backend | "Set up Terraform with S3 backend" (no encryption params) |
| No resource tagging | "Provision an EC2 instance with Terraform" |

---

## 3. Vulnerable Code Examples

### 3.1 Hardcoded Database Credentials

```hcl
# 💀 VULNERABLE — variables.tf
variable "db_password" {
  description = "Database password"
  type        = string
  default     = "P@ssw0rd123!" # 💀 Hardcoded in source
}

# 💀 VULNERABLE — main.tf
resource "aws_db_instance" "main" {
  identifier     = "myapp-db-prod"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.medium"
  username       = "dbadmin"
  password       = var.db_password # Still hardcoded via default
  skip_final_snapshot = true       # 💀 Production DB without final snapshot!
  storage_encrypted   = false      # 💀 No encryption at rest
  publicly_accessible = true       # 💀 Publicly accessible
}
```

### 3.2 Publicly Accessible S3 Bucket

```hcl
# 💀 VULNERABLE — Complete S3 misconfiguration
resource "aws_s3_bucket" "uploads" {
  bucket = "myapp-user-uploads"
  acl    = "public-read"
}

resource "aws_s3_bucket_website_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.uploads.arn}/*"
      }
    ]
  })
}
```

### 3.3 Overly Permissive Security Group

```hcl
# 💀 VULNERABLE — Wide-open security group
resource "aws_security_group" "web" {
  name_prefix = "web-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # 💀 All traffic, all ports, all IPs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### 3.4 Cleartext State Backend (Azure)

```hcl
# 💀 VULNERABLE — Azure backend without HTTPS enforcement
terraform {
  backend "azurerm" {
    storage_account_name = "mytfstate"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
    # SAS token transmitted over cleartext HTTP on some versions
    # (CVE-2019-19316)
  }
}
```

---

## 4. Secure Code Fix

### 4.1 Sensitive Variables with `sensitive = true`

```hcl
# ✅ SECURE — variables.tf
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true # Never printed in plan/output
}

variable "db_username" {
  description = "Database username"
  type        = string
  sensitive   = true
}

# ✅ SECURE — terraform.tfvars (gitignored!)
db_password = "replace-with-vault-secret-or-env-var"
db_username = "dbadmin"

# ✅ SECURE — main.tf
resource "aws_db_instance" "main" {
  identifier     = "myapp-db-prod"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.medium"
  username       = var.db_username
  password       = var.db_password

  # Security hardening
  storage_encrypted   = true                 # ✅ Encryption at rest
  skip_final_snapshot = false                # ✅ Keep final snapshot
  publicly_accessible = false                # ✅ Private only
  backup_retention_period = 30               # ✅ Backup retention

  tags = {
    Name        = "myapp-db-prod"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### 4.2 IAM Least Privilege

```hcl
# ✅ SECURE — IAM with least privilege
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-s3-read-specific"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount": data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}
```

### 4.3 S3 Bucket Security

```hcl
# ✅ SECURE — S3 bucket with full security controls
resource "aws_s3_bucket" "data" {
  bucket = "myapp-data-${data.aws_caller_identity.current.account_id}"
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Block non-TLS requests
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  })
}
```

### 4.4 Secure Remote State Backend

```hcl
# ✅ SECURE — S3 backend with encryption and locking
terraform {
  backend "s3" {
    bucket         = "myapp-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "terraform-state-locks"

    # Access controlled via bucket policy and IAM
  }
}
```

### 4.5 Dedicated VPC with Network Isolation

```hcl
# ✅ SECURE — Custom VPC with proper network segmentation
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "myapp-vpc"
    Environment = "production"
  }
}

# Private subnets for internal resources
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "myapp-private-${count.index}"
    Type        = "private"
    Environment = "production"
  }
}

# Restricted security group — only necessary ports
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from bastion only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "web-sg"
    Environment = "production"
  }
}
```

### 4.6 Mandatory Tags with Validation

```hcl
# ✅ SECURE — Precondition to enforce tagging
variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "owner" {
  description = "Resource owner email"
  type        = string
}

locals {
  common_tags = {
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "terraform"
    CreatedAt   = timestamp()
  }
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id

  # Encryption
  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  root_block_device {
    encrypted = true
    kms_key_id = aws_kms_key.ebs.arn
  }

  tags = local.common_tags
}
```

---

## 5. Real CVEs (Verified via NVD)

### CVE-2018-9057 — Weak IAM Password Generation (AWS Provider)
- **Published:** 2018-03-27
- **CVSS:** 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-332 (Insufficient Entropy in PRNG)
- **Affected:** Terraform AWS provider <= 1.12.0
- **Description:** The `aws_iam_user_login_profile` resource in the AWS provider used an inappropriate PRNG algorithm and seeding for generating IAM login passwords. The generated passwords had insufficient entropy, making them predictable to remote attackers who can enumerate IAM users. An attacker who knows the password generation algorithm and seeding can compute the password for newly created IAM users.
- **Fix:** Upgrade to AWS provider > 1.12.0, which uses a cryptographically secure PRNG.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2018-9057

### CVE-2019-19316 — Cleartext State Transmission (Azure Backend)
- **Published:** 2019-12-02
- **CVSS:** 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
- **Affected:** Terraform < 0.12.17
- **Description:** When using the Azure backend with a Shared Access Signature (SAS) token, Terraform transmits the SAS token and state snapshot over cleartext HTTP instead of HTTPS. An attacker on the same network can intercept the SAS token (gaining access to the storage container) and the Terraform state (containing all infrastructure secrets).
- **Fix:** Upgrade to Terraform >= 0.12.17, which enforces HTTPS for Azure backend communication.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2019-19316

### CVE-2020-15511 — Terraform Enterprise Signup Bypass
- **Published:** 2020-07-30
- **CVSS:** 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
- **Affected:** Terraform Enterprise <= v202006-1
- **Description:** Terraform Enterprise contained a default signup page that allowed user registration even when the organization disabled self-signup. This bypassed SAML enforcement, allowing unauthorized users to create accounts on the TFE instance.
- **Fix:** Upgrade to TFE >= v202007-1, which disables the signup page when SAML enforcement is enabled.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-15511

### CVE-2021-3153 — TFE 2FA Enforcement Bypass
- **Published:** 2021-03-26
- **CVSS:** 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **CWE:** NVD-CWE-noinfo
- **Affected:** Terraform Enterprise <= v202102-2
- **Description:** Terraform Enterprise failed to enforce an organization-level setting that required all users within an organization to have two-factor authentication (2FA) enabled. Users could disable their own 2FA despite the organizational requirement.
- **Fix:** Upgrade to TFE >= v202103-1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-3153

### CVE-2021-30476 — Vault Provider GCE Auth Misconfiguration
- **Published:** 2021-05-11
- **CVSS:** 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — NVD primary; CWE: NVD-CWE-noinfo
- **Affected:** Terraform Vault provider < 2.19.1
- **Description:** The `vault_gcp_auth_backend` resource did not correctly validate or configure GCE-type bound labels for Vault's GCP authentication method. This could allow a GCE instance with matching but unauthorized labels to authenticate to Vault.
- **Fix:** Upgrade to Vault provider >= 2.19.1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-30476

### CVE-2020-13359 — GitLab Terraform API State Overwrite
- **Published:** 2020-11-19
- **CVSS:** 7.6 HIGH (AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N)
- **Affected:** GitLab CE/EE 12.10+ to 13.5.2
- **Description:** The GitLab Terraform API exposed the object storage signed URL on the delete operation. A project maintainer could use this to overwrite the Terraform state file, bypassing audit controls and potentially corrupting or hijacking the managed infrastructure.
- **Fix:** Upgrade GitLab to >= 13.3.9, 13.4.5, or 13.5.2 depending on the release track.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-13359

### CVE-2021-36230 — TFE Privilege Escalation
- **Published:** 2021-08-10
- **CVSS:** 8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Affected:** Terraform Enterprise <= v202106-1
- **Description:** Terraform Enterprise did not properly perform authorization checks on API requests executed using a run token. An attacker with a run token could escalate privileges to organization-level access, including modifying workspace settings and viewing sensitive variables.
- **Fix:** Upgrade to TFE >= v202107-1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-36230

### CVE-2022-25374 — TFE Sensitive Data in HTTP Logs
- **Published:** 2022-03-25
- **CVSS:** 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — NVD primary
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected:** Terraform Enterprise v202112-1 through v202201-2
- **Description:** Terraform Enterprise logged inbound HTTP request bodies in a manner that could capture sensitive data such as API tokens, variables, and run outputs. An attacker with access to the TFE server logs could extract secrets.
- **Fix:** Upgrade to TFE >= v202202-1, which sanitizes sensitive data from logs.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2022-25374

### CVE-2019-8944 — Octopus Deploy Terraform Variable Exposure
- **Published:** 2019-02-20
- **CVSS:** 6.5 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected:** Octopus Deploy < 2019.1.8
- **Description:** Octopus Deploy logged sensitive Terraform output variables during the deployment step. Remote authenticated users with access to deployment logs could view sensitive values (database passwords, API keys) that should have been restricted.
- **Fix:** Upgrade Octopus Deploy to >= 2019.1.8.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2019-8944

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

## Semgrep Patterns for Terraform Security

Below are key Semgrep rule IDs for scanning AI-generated Terraform:

| Rule ID | Description |
|---|---|
| `tfsec-aws-iam-no-policy-wildcards` | Wildcard IAM actions or resources |
| `tfsec-aws-s3-block-public-acls` | S3 bucket public ACLs enabled |
| `tfsec-aws-s3-encryption-customer-key` | S3 bucket without KMS encryption |
| `tfsec-aws-s3-ignore-public-acls` | S3 bucket public ACLs not ignored |
| `tfsec-aws-s3-no-public-buckets` | S3 bucket publicly accessible |
| `tfsec-aws-s3-restrict-bucket-public-access` | S3 bucket public access not restricted |
| `tfsec-aws-s3-specify-public-access-block` | Missing S3 public access block |
| `tfsec-aws-ec2-require-imdsv2` | EC2 IMDSv1 enabled |
| `tfsec-aws-rds-encrypt-instance-storage-data` | RDS not encrypted |
| `tfsec-aws-ebs-encryption-customer-key` | EBS not encrypted |
| `tfsec-aws-vpc-no-default-vpc` | Resources using default VPC |
| `tfsec-aws-rds-no-public-db-access` | RDS publicly accessible |
| `tfsec-aws-specify-security-group-ports` | Security group port range too wide |
| `tfsec-aws-restrict-ingress-common-ports-all` | Ingress from 0.0.0.0/0 on common ports |

Run with: `semgrep --config=auto --config=p/tfsec .`

---

## References

- Terraform Sensitive Variables: https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables
- Terraform Security Best Practices: https://developer.hashicorp.com/terraform/cloud-docs/security
- Terraform State Backend Configuration: https://developer.hashicorp.com/terraform/language/settings/backends/configuration
- Checkov Terraform Scanning: https://www.checkov.io/
- tfsec (Terraform security scanner): https://github.com/aquasecurity/tfsec
- Semgrep Terraform Rules: https://semgrep.dev/playground?registry=tfsec
- HashiCorp Security Advisories: https://discuss.hashicorp.com/c/security-advisories/
- NVD Terraform CVEs: https://nvd.nist.gov/vuln/search/results?query=terraform+hashicorp&search_type=all
- CVE-2018-9057: https://nvd.nist.gov/vuln/detail/CVE-2018-9057
- CVE-2019-19316: https://nvd.nist.gov/vuln/detail/CVE-2019-19316
- CVE-2020-15511: https://nvd.nist.gov/vuln/detail/CVE-2020-15511
- CVE-2020-13359: https://nvd.nist.gov/vuln/detail/CVE-2020-13359
- CVE-2021-30476: https://nvd.nist.gov/vuln/detail/CVE-2021-30476
- CVE-2021-36230: https://nvd.nist.gov/vuln/detail/CVE-2021-36230
- CVE-2022-25374: https://nvd.nist.gov/vuln/detail/CVE-2022-25374
- OpenTofu Security: https://opentofu.org/docs/security/
- AWS Well-Architected Framework — Security Pillar: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
