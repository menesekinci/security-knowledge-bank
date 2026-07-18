---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

- **AI doesn't set security headers** — Headers are "ops/deployment concern," not code.
- **AI-generated app code skips middleware** — No helmet.js (Node), no secure (Python), no security middleware.
- **AI uses wildcard origins** — "To not break CORS." But weakens all other protections.
- **AI doesn't differentiate environments** — Dev config ships to production unchanged.

---