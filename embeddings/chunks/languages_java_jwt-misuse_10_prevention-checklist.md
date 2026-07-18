---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
heading: "Prevention Checklist"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, algorithm, confusion, java, language-vuln, overview, vulnerability]
chunk: 10/10
---

## Prevention Checklist

1. **Always enforce `requireSignature()`** — Reject `alg: none` tokens.
2. **Use strong keys** — Minimum 256-bit secret for HMAC; 2048-bit RSA; use P-256 for EC.
3. **Store secrets in vault** — Never hardcode JWT secrets in source code.
4. **Always set and check expiration** — Use 15-minute access tokens, longer-lived refresh tokens.
5. **Validate `aud` and `iss` claims** — Ensure the token is for your application.
6. **Use `jjwt` 0.12+, `nimbus-jose-jwt` 9.37.2+, or `jose4j` 0.9.4+** — Latest versions have algorithm-confusion protections and the PBES2 DoS fixes; run on a patched JDK to avoid CVE-2022-21449.
7. **Use short-lived access tokens + refresh tokens** — Minimizes impact of token theft.
8. **Avoid storing sensitive data in JWT** — Payload is base64-encoded, not encrypted (unless using JWE).
9. **Implement token revocation** — Server-side blocklist for compromised tokens.
10. **Use JWE for sensitive claims** — Encrypted JWTs if you must include PII.