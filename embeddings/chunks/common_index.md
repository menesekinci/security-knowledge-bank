---
source: "common/index.md"
title: "🧬 Common Security Vulnerabilities"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, vulnerabilities]
---

# 🧬 Common Security Vulnerabilities

> Cross-cutting, framework and platform independent security issues.
> Every vulnerability here must be kept in mind when generating code with AI.

---

## 📋 Vulnerabilities

1. [🔴 Injection Attacks](injection.md) — SQL, NoSQL, OS Command, LDAP, Expression Language
2. [🔴 Broken Authentication](broken-auth.md) — Session hijacking, credential stuffing, JWT pitfalls
3. [🔴 Cross-Site Scripting (XSS)](xss.md) — Reflected, Stored, DOM-based, CSP bypass
4. [🔴 Insecure Deserialization](deserialization.md) — Pickle, YAML, Java serialization, JSON attacks
5. [🔴 Cryptographic Failures](crypto.md) — Weak ciphers, hardcoded keys, bad RNG, hashing mistakes
6. [🟠 Insecure Direct Object References (IDOR)](idor.md)
7. [🟠 Security Misconfiguration](misconfiguration.md) — Default creds, debug enabled, CORS misconfig
8. [🟠 Server-Side Request Forgery (SSRF)](ssrf.md)
9. [🟠 Path Traversal](path-traversal.md)
10. [🟠 Race Conditions / TOCTOU](race-conditions.md)
11. [🔴 Supply Chain Attacks](supply-chain.md) — Dependency confusion, typo-squatting, malicious packages
12. [🔴 Memory Safety Violations](memory-safety.md) — Buffer overflow, use-after-free (low-level languages)
13. [🟡 Business Logic Flaws](business-logic.md) — Discount abuse, rate limit bypass, step skipping
14. [🟡 Logging & Monitoring Failures](logging.md)
15. [🟡 Server-Side Template Injection (SSTI)](ssti.md)
16. [🟡 Mass Assignment / Auto Binding](mass-assignment.md)
17. [🟡 Regular Expression DoS (ReDoS)](redos.md)
18. [🟡 Open Redirect](open-redirect.md)
19. [🟡 HTTP Request Smuggling](http-smuggling.md)
20. [🟡 WebSocket Security](websocket.md)
21. [🟡 Prototype Pollution (JS side but common impact)](prototype-pollution.md)
22. **[🔴 Zero-Day / N-Day Exploits](zero-day.md)**
23. **[🔴 RAG Poisoning](rag-poisoning.md)** — Knowledge base poisoning, document injection, embedding poisoning, indirect prompt injection in Retrieval-Augmented Generation
24. **[🔴 OAuth 2.0 Security](oauth2-security.md)** — Implicit grant risks, redirect URI manipulation, CSRF with state, PKCE misuse, token leakage
25. **[🟡 Security Logging & Forensics](logging-forensics.md)** — Audit trails, SIEM integration, log injection, log forgery, GDPR compliance
26. **[🟡 CORS Deep Dive](cors-deep.md)** — Preflight bypass, null origin, credentials mode, wildcard vs specific origins, Vibe Coding misconfigs
27. **[🟡 CSP Deep Dive](csp-deep.md)** — CSP bypass techniques, nonce vs hash, report-uri/report-to, strict CSP
28. **[🟡 HTTP Security Headers](http-headers-security.md)** — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy
29. **[🟡 Secure CI/CD](secure-cicd.md)** — pipeline secrets, poisoned pipeline execution, artifact integrity
30. **[🟡 Security Testing](security-testing.md)** — SAST/DAST/SCA strategy for AI-generated code
31. **[🟡 Incident Response](incident-response.md)** — triage, containment, forensics handoff
32. **[🟡 Secure Code Review](secure-code-review.md)** — review checklist for vibe-coded PRs

### Subdirectories

- [api-security/](api-security/) — REST, GraphQL, gRPC, Webhooks
- [cloud-security/](cloud-security/) — AWS, Docker, Kubernetes, cloud misconfig deep-dive
- [database/](database/) — PostgreSQL, MySQL, NoSQL (MongoDB, Redis, Elasticsearch)
- [engineering/](engineering/) — Security engineering principles, threat modeling, architecture
- [server/](server/) — Nginx, Apache, TLS/SSL, Linux hardening, LB/CDN/WAF
- [mq/](mq/) — RabbitMQ, Kafka, Redis PubSub security
- [case-studies/](case-studies/) — common case studies

---

**OWASP Top 10:2021** and **CWE Top 25:2024** cross-referenced.
For each vulnerability: description, how it manifests in Vibe Coding, examples of harmful/harmless code, prevention methods.
