---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "3. Vulnerable Code Examples"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 5/11
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