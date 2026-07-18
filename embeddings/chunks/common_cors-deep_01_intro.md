---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "intro"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 1/10
---

# CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs

**CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains), CWE-346 (Origin Validation Error)
**OWASP Top 10:2021:** A01 — Broken Access Control
**Related:** CWE-918 (SSRF), CWE-79 (XSS)

---