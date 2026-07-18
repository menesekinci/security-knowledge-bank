---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "6. Quick Reference: Top 10 OWASP:2021 × AI Code"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 7/8
---

## 6. Quick Reference: Top 10 OWASP:2021 × AI Code

| OWASP Top 10 | AI Vulnerability Rate | What to Check |
|-------------|----------------------|---------------|
| **A01: Broken Access Control** | 🔴 High | AI often forgets authorization checks |
| **A02: Cryptographic Failures** | 🔴 High | AI uses outdated/weak crypto APIs |
| **A03: Injection** | 🔴 High | SQL, command, expression injection |
| **A04: Insecure Design** | 🟡 Medium | Missing rate limiting, business logic flaws |
| **A05: Security Misconfiguration** | 🟡 Medium | Debug mode, permissive CORS |
| **A06: Vulnerable Components** | 🔴 High | Hallucinated or outdated packages |
| **A07: Identification/Auth Failures** | 🔴 High | Weak password checks, session issues |
| **A08: Data Integrity Failures** | 🟢 Low | Deserialization in ML contexts |
| **A09: Logging/Monitoring** | 🟢 Low | No logging, verbose error messages |
| **A10: SSRF** | 🟡 Medium | User-controlled URLs fetched by server |

---