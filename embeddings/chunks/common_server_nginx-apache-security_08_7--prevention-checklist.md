---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "7. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 8/10
---

## 7. Prevention Checklist

- [ ] **Disable server tokens/signatures** — `server_tokens off` (Nginx), `ServerSignature Off` + `ServerTokens Prod` (Apache), remove `Server` header (Caddy)
- [ ] **Disable directory listing** — `autoindex off` (Nginx), `Options -Indexes` (Apache), no `file_server browse` (Caddy)
- [ ] **Enforce TLS 1.2+ only** — Block TLS 1.0/1.1 and SSLv2/v3
- [ ] **Set strong cipher suites** — Use Mozilla's Intermediate or Modern profile
- [ ] **Enable security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- [ ] **Implement rate limiting** — `limit_req`/`limit_conn` (Nginx), `mod_evasive` (Apache), `rate_limit` (Caddy)
- [ ] **Set request body/buffer limits** — `client_max_body_size`, `client_body_buffer_size`, `client_header_buffer_size` (Nginx); `LimitRequestBody` (Apache)
- [ ] **Restrict reverse proxy targets** — Never proxy to user-controlled URLs; use whitelists
- [ ] **Validate `Host` and `Origin` headers** — Prevent host header injection and CSWSH
- [ ] **Secure error pages** — Custom error documents without version information
- [ ] **Restrict admin interfaces** — `mod_info`/`mod_status` to localhost only; disable Caddy admin in production
- [ ] **Enable access and error logging** — Structured JSON logs, log rotation, avoid logging sensitive data (tokens, passwords)
- [ ] **Use minimal privilege** — Run workers as non-root user; restrict file permissions
- [ ] **Regular updates** — Subscribe to Nginx [security advisories](https://nginx.org/en/security_advisories.html), Apache [vulnerability announcements](https://httpd.apache.org/security_report.html), Caddy [GitHub releases](https://github.com/caddyserver/caddy/releases)

---