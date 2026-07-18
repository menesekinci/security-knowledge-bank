---
source: "languages/rust/web-framework-risks.md"
title: "Web Framework Risks — Actix, Axum, Rocket Common Misconfigurations"
heading: "Prevention Checklist"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [checklist, common, cross-framework, cves, framework-specific, language-vuln, overview, prevention, real, risks]
chunk: 6/6
---

## Prevention Checklist

1. **Validate all inputs** — Use `validator` crate's `Validate` derive on structs for length, format, and range checks.
2. **Use type-safe extractors** — Never extract raw `String` from path/query; use `Path<u64>`, `Query<ValidatedParams>`.
3. **Configure CORS strictly** — Allow only specific origins, not `Any`.
4. **Add rate limiting** — `tower-governor` for Axum, `actix-governor` for Actix.
5. **Implement authentication middleware** — Never trust user-supplied session data without verification.
6. **Set security headers** — Use `tower-http`'s `SetResponseHeaderLayer` for HSTS, CSP, X-Frame-Options.
7. **Log securely** — Don't log tokens, passwords, or PII.
8. **Use `cargo audit`** — Vulnerabilities in `hyper`, `h2`, `tokio` affect all Rust web apps.
9. **Set body size limits** — Prevent DoS via large request bodies: `DefaultBodyLimit::max(256 * 1024)`.
10. **Generate CSRF tokens** — For Rocket, use `rocket_csrf`; for Axum/Actix, use `tower-sessions` with CSRF protection.