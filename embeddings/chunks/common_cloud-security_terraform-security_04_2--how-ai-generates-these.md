---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "2. How AI Generates These Vulnerabilities"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 4/11
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