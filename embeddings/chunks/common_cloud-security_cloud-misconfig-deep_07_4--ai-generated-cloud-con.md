---
source: "common/cloud-security/cloud-misconfig-deep.md"
title: "Cloud Misconfiguration Deep Dive"
heading: "4. AI-Generated Cloud Config Pitfalls"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud, cloud-security, credential, environment, overview, table, variable]
chunk: 7/9
---

## 4. AI-Generated Cloud Config Pitfalls

Cloud Security Alliance research (2026) found that 45% of AI-generated cloud configuration snippets contain security vulnerabilities.

### AI-Generated Terraform with Security Flaws

```hcl
# AI-GENERATED VULNERABLE: Open S3 bucket with SSE-S3
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
  # AI forgot to add:
  # - access controls
  # - encryption
  # - versioning
  # - public access blocks
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  # AI missed this entirely!
  # Without it, bucket is publicly accessible by default
}
```

### Secure AI-Corrected Terraform

```hcl
# SECURE: Terraform with all security controls
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-${var.environment}"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.data.arn
      }
    }
  }
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny unencrypted operations
data "aws_iam_policy_document" "s3_encryption" {
  statement {
    effect = "Deny"
    actions = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }
}
```

### AI Vibe Coding — Cursor .env Leak (2024 Incident)

A significant 2024 incident revealed that **Cursor** (AI code editor) was reading `.env` file contents and sending them to its servers for tab completion features. This happened even when files were listed in `.gitignore`, because the AI assistant's context gathering ignored the ignore rules. The incident highlighted a fundamental tension: AI assistants need context, but that context includes secrets.

**Lessons:**
1. Never put real credentials in local `.env` files during AI-assisted development
2. Use `.env.example` files with placeholder values for AI context
3. Review all AI-generated code before running with real credentials

---