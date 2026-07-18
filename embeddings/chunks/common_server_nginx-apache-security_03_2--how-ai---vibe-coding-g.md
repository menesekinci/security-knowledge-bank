---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "2. How AI / Vibe Coding Generates These Issues"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 3/10
---

## 2. How AI / Vibe Coding Generates These Issues

Typical LLM prompts that produce insecure configurations:

| Prompt | What AI Returns | Security Gap |
|--------|----------------|--------------|
| "Generate Nginx config for my Node.js app" | Basic reverse proxy, no SSL, `server_tokens on`, no headers | No TLS, info leakage, no hardening |
| "Docker with Nginx + Alpine" | Minimal `nginx.conf`, default everything | No limits, no health checks, directory listing possibly on |
| "Apache virtual host for my PHP site" | `<VirtualHost>` with `Options +Indexes`, no HSTS | Directory listing, no TLS enforcement |
| "Caddyfile for static site" | `file_server browse` without auth | Full directory listing |
| "Add HTTPS to my Nginx config" | Self-signed cert, TLSv1.0, weak cipher suite | Incomplete TLS setup |
| "Rate limit my API" | `limit_req_zone` with burst=100, no dry-run testing | Either too permissive or too restrictive |
| "Docker Compose with reverse proxy" | Open `proxy_pass`, no access control | SSRF via forwarded host headers |

**Vibe coding amplification:** When developers iterate quickly using "make it work" prompts, security configuration is deferred. Each regeneration preserves insecure defaults because the prompt doesn't explicitly override them.

---