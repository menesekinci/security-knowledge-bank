---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "SSRF Defense Layers"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 7/10
---

## SSRF Defense Layers

| Layer | Defense |
|---|---|
| Protocol allowlist | Only allow `http:` / `https:` — block `file:`, `gopher:`, `dict:`, `ftp:` |
| Hostname allowlist | Only allow pre-approved domains (best) |
| IP deny list | Block private, link-local, loopback ranges |
| DNS resolution check | Resolve to IP, verify it's not internal |
| Disable redirects | Don't automatically follow 3xx redirects |
| Timeout | Set short timeouts (3-5s) |
| Rate limiting | Limit requests per user to prevent scanning |

---