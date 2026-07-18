---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

- **AI generates debug configurations:** `DEBUG=True`, `NODE_ENV=development` left in production
- **AI uses framework defaults:** Many frameworks ship with insecure defaults (e.g., default admin passwords)
- **AI doesn't set security headers:** Generated apps often lack CSP, HSTS, X-Frame-Options
- **AI generates permissive CORS:** `Access-Control-Allow-Origin: *` for everything
- **Hardcoded config values:** `DB_HOST=localhost`, `ADMIN_PASSWORD=admin` scattered through generated code