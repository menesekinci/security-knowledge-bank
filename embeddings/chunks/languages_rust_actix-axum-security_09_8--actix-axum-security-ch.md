---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "8. Actix/Axum Security Checklist"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 9/10
---

## 8. Actix/Axum Security Checklist

- [ ] All path/query extractors validate input type, length, and format
- [ ] JSON extractors use validation crates (validator, garde)
- [ ] Middleware order: Logging → CORS → Auth → Rate Limit → Routes
- [ ] WebSocket connections validate tokens before upgrade
- [ ] WebSocket actions authorize each message, not just the connection
- [ ] CORS is restricted to specific origins
- [ ] Rate limiting applied to auth endpoints
- [ ] Security headers (HSTS, CSP, XFO, XCTO) added via middleware
- [ ] Request body size is limited
- [ ] `unsafe` blocks reviewed and documented
- [ ] Sensitive data not leaked in error responses
- [ ] Logging does not include tokens, passwords, or PII

---