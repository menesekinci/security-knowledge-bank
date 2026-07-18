---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 15
total_chunks: 16
heading: "13. Common AI-Produced Misconfigurations"
---

## 13. Common AI-Produced Misconfigurations

1. **Helmet not installed or placed too late** — Missing security headers
2. **No rate limiting** — Brute force vulnerability
3. **Weak/static session secret** — `express-session` with "keyboard cat"
4. **`saveUninitialized: true`** — Wastes resources on anonymous sessions
5. **`secure: false` for session cookies** — Auth cookies over HTTP
6. **`cors()` with no options** — Accepts all origins
7. **No CSRF protection for APIs** — Missing anti-forgery tokens
8. **Error details in production** — Stack traces leaked to clients
9. **`express.json({ limit: "10mb" })` before auth** — DoS vector
10. **No input validation** — Missing schema/param validation (mass assignment)
11. **@fastify/express URL normalization bypass** — CVE-2026-33808 pattern

---