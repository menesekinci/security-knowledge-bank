---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "What Are HTTP Security Headers?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 2/10
---

## What Are HTTP Security Headers?

HTTP security headers are **response headers** that tell browsers how to behave when handling a web application. They provide defense-in-depth against a wide range of attacks — XSS, clickjacking, MIME-type sniffing, protocol downgrades, and information leakage.

**The problem:** These headers are almost universally missing or misconfigured in AI-generated code. They're "invisible" to developers because they don't change visible behavior — until an attack succeeds.

### Global Adoption Statistics

| Header | Adoption Rate (2024) | Trend |
|--------|---------------------|-------|
| HSTS | 25% of top 1M sites | ⬆️ Increasing |
| X-Frame-Options | 40% | ➡️ Stable |
| X-Content-Type-Options | 35% | ➡️ Stable |
| CSP | 20% | ⬆️ Increasing |
| Referrer-Policy | 18% | ⬆️ Increasing |
| Permissions-Policy | 8% | ⬆️ Growing |
| All 5+ headers | <5% | ⬆️ Slowly improving |

**Source:** https://web.dev/security-headers/

---