---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 2
total_chunks: 10
heading: "Overview"
---

## Overview

JSON Web Tokens (JWTs) are the de facto standard for authentication and authorization in modern Java web applications. Java has mature JWT libraries (JJWT 0.12+, Nimbus JOSE+JWT, Auth0 java-jwt), but their APIs leave room for critical security mistakes. AI-generated Java code makes the same JWT errors consistently:

1. **Algorithm confusion** — Accepting `alg: "none"` or mixing HMAC and RSA
2. **Weak signing keys** — Hardcoded, short, or guessable secrets
3. **No expiration validation** — Tokens live forever
4. **Claim injection** — Overwriting critical claims in untrusted input