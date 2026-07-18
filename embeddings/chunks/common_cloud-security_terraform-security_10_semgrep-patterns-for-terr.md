---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "Semgrep Patterns for Terraform Security"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 10/11
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