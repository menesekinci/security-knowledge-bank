---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

- **AI defaults to `Access-Control-Allow-Origin: *`** — "To allow all frontends to connect."
- **AI couples wildcard with `Access-Control-Allow-Credentials: true`** — Creates a CORS vulnerability that browsers explicitly block, but many bypass techniques exist.
- **AI reflects Origin headers** — Reads `Origin` from request and echoes it back without validation.
- **AI enables CORS methods/permissive** — Allows `PUT`, `DELETE`, `PATCH`, and custom headers on all routes.
- **AI doesn't handle preflight caching** — Sets `Access-Control-Max-Age` to days, making bypass persistent.
- **AI misuses `null` origin** — Whitelists `null` for local development but leaves it in production.

---