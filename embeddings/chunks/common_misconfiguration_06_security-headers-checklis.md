---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Security Headers Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 6/9
---

## Security Headers Checklist

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Prevents XSS and data injection |
| `Strict-Transport-Security` | Enforces HTTPS |
| `X-Content-Type-Options: nosniff` | Prevents MIME sniffing |
| `X-Frame-Options: DENY` | Prevents clickjacking |
| `Referrer-Policy` | Controls referrer info leakage |
| `Permissions-Policy` | Restricts browser feature access |
| `Cross-Origin-Embedder-Policy` | COEP for cross-origin isolation |

---