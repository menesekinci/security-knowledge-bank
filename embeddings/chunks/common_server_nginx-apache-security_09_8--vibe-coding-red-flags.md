---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "8. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 8. Vibe-Coding Red Flags

Watch for these patterns in AI-generated web server configs:

1. **No `server_tokens off`** — The most common omission; AI defaults to showing versions
2. **`autoindex on` or `+Indexes`** — Directory listing exposed, especially in "simple static file server" configs
3. **HTTP-only (port 80) without redirect** — "listen 80" with no TLS upgrade
4. **`ssl_protocols TLSv1 TLSv1.1`** — Old protocols explicitly enabled
5. **`ssl_ciphers` with RC4, DES, or EXPORT** — Weak cipher suites included
6. **`proxy_pass http://$variable`** — User-controlled proxy target = instant SSRF
7. **No security headers at all** — The config works but provides zero browser-side protection
8. **`location / { alias /path; }`** — Missing trailing slash on `alias` enables path traversal
9. **`debug` mode in Caddy** — Verbose logging exposes request internals
10. **`AllowOverride All`** — Every directory gets `.htaccess` override, risky for shared hosting
11. **`Listen 0.0.0.0:80`** — Binds to all interfaces without consideration
12. **No `limit_req` / `limit_conn`** — APIs exposed to unlimited requests
13. **`proxy_pass` without `proxy_set_header Host $host`** — Backend receives wrong Host header
14. **`return 301 http://...`** — Redirect to HTTP instead of HTTPS
15. **No `client_max_body_size`** — Default 1MB may be too small or too large depending on application
16. **`tls internal` in Caddy production** — Self-signed certificate in production environments
17. **`server_name _;` without proper access control** — Catch-all server blocks leak data
18. **Exposing health check endpoints** — `/health`, `/status`, `/ping` without restriction
19. **No `internal` directive for sensitive locations** — Nginx `internal` prevents direct external access
20. **`add_header` in `location` block without `always`** — Headers not sent for error responses

---