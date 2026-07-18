---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "Overview"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 2/11
---

## Overview

Terraform and OpenTofu are the dominant Infrastructure as Code (IaC) tools, and AI code generators are routinely tasked with generating Terraform configurations for AWS, Azure, GCP, and other providers. The AI-generated patterns are especially dangerous because they create infrastructure that:

1. Is **persistent** and **cost-incurring** (not easily thrown away like buggy code)
2. Often has **public network exposure** (S3 buckets, security groups, load balancers)
3. **Stores secrets in state files** that are frequently stored in S3/GCS buckets or local files
4. **Lacks audit trails** — no logging, no tagging, no monitoring

The Terraform ecosystem has seen CVEs in the AWS provider (weak IAM password generation), cleartext state transmission (Azure backend), Terraform Enterprise (auth bypass, 2FA bypass, log leakage), and GitLab's Terraform API (state overwrite).

---