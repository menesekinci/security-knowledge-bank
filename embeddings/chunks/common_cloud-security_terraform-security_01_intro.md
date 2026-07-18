---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "intro"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 1/11
---

# Terraform & OpenTofu IaC Security Deep Dive

> **Category:** Cloud Security / Infrastructure as Code  
> **Focus:** Hardcoded secrets, overly permissive IAM, public S3 buckets, default VPC, state file exposure, missing encryption, insecure state backends  
> **Severity:** High  
> **CWE:** CWE-312 (Cleartext Storage of Sensitive Info), CWE-200 (Info Exposure), CWE-284 (Access Control), CWE-319 (Cleartext Transmission), CWE-332 (Weak PRNG), CWE-532 (Info Exposure via Logs)  
> **AI Generation Risk:** High  
> **Last Updated:** July 2026

---