---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
heading: "Advanced SSRF With Cloud Metadata"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [advanced, code, cves, go, language-vuln, overview, real, ssrf, vulnerable]
chunk: 5/8
---

## Advanced SSRF With Cloud Metadata

The most common SSRF target: cloud provider metadata endpoints.

| Cloud | Metadata URL |
|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` |

An SSRF that can reach these endpoints leaks IAM credentials, instance metadata, and potentially cloud API keys.