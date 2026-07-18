---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "CORS Headers Reference"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 4/10
---

## CORS Headers Reference

| Header | Description | Direction |
|--------|-------------|-----------|
| `Access-Control-Allow-Origin` | Which origins are allowed | Response |
| `Access-Control-Allow-Credentials` | Whether credentials (cookies) can be sent | Response |
| `Access-Control-Allow-Methods` | Which HTTP methods are allowed (for preflight) | Response |
| `Access-Control-Allow-Headers` | Which headers can be used (for preflight) | Response |
| `Access-Control-Expose-Headers` | Which headers the browser can access | Response |
| `Access-Control-Max-Age` | How long to cache preflight result | Response |
| `Access-Control-Request-Method` | Which method will be used (preflight) | Request |
| `Access-Control-Request-Headers` | Which headers will be used (preflight) | Request |
| `Origin` | Where the request originated | Request |

---