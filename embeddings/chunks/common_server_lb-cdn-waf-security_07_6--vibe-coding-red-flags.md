---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "6. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 7/8
---

## 6. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Configure Cloudflare for my web app" | Flexible SSL, grey-cloud DNS, WAF disabled | Full (Strict) SSL, proxied DNS, WAF enabled |
| "Add WAF to my AWS API" | Default allow, no rules, no logging | Default block, managed rules, rate limiting, logging |
| "Set up health checks" | Public `/health` endpoint with no auth | Internal IP-restricted or secret-header health check |
| "Deploy a load balancer" | Default credentials, admin panel exposed | Hardened config, auth required, admin on separate port |
| "Cache my API responses" | `Cache-Control: public, max-age=86400` on all routes | Private cache for auth responses, short TTL for dynamic | 
| "Optimize CDN performance" | Cache everything including user profiles | Vary cache by auth, exclude sensitive routes |
| "Add rate limiting" | No rate limiting on login endpoints | Rate-based WAF rule: 5 attempts per minute per IP |
| "Configure CORS for CDN" | `Access-Control-Allow-Origin: *` with credentials | Explicit allowed origins, validate Origin header |
| "Set up SSL/TLS" | "Flexible" mode (traffic encrypted to CDN only) | Full (Strict) — end-to-end encryption |
| "Write a Nginx reverse proxy config" | Public status endpoint, no connection limits | Restrict status, set timeouts, rate limit upstreams |

---