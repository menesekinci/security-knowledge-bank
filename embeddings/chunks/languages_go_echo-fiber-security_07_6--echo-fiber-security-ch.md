---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "6. Echo/Fiber Security Checklist"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 7/8
---

## 6. Echo/Fiber Security Checklist

- [ ] All bind/body parsers validate input with `validator` or equivalent
- [ ] DTOs separate from domain models (no mass assignment)
- [ ] SQL queries use parameterized placeholders (`$1`, `?`), never string formatting
- [ ] CORS restricted to specific origins (no wildcard with credentials)
- [ ] CSRF middleware enabled for session-based auth
- [ ] Rate limiting applied to auth endpoints
- [ ] Error responses are generic (no stack traces, no SQL details)
- [ ] JWT validation checks signing algorithm (`alg`)
- [ ] Session IDs are server-generated (not user-supplied)
- [ ] Middleware order: CORS → Rate Limit → Auth → CSRF
- [ ] Security headers set (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- [ ] Request body size limited with `MaxBytesReader` or Fiber's body limit config
- [ ] Fiber version ≥ 2.52.1 (CORS + session fix)
- [ ] Upload directory is outside web root
- [ ] Logging doesn't include tokens, passwords, or PII

---