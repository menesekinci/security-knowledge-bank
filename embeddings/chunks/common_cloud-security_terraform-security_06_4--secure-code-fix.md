---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "4. Secure Code Fix"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 6/11
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