---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "1. What Counts as a Secret"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 2/8
---

## 1. What Counts as a Secret

A secret is any credential or cryptographic material that, if disclosed, could be used to authenticate or authorize access to a system, data, or resource. The most common categories:

| Category | Examples | Impact if Leaked |
|---|---|---|
| **API keys** | Cloud provider keys (AWS AK/SK), SaaS API tokens | Direct resource access, data exfiltration |
| **Passwords** | Database passwords, admin credentials, application passwords | Authentication bypass, lateral movement |
| **Tokens** | OAuth access tokens, JWT signing keys, session secrets | Session hijacking, token forgery |
| **Certificates** | TLS private keys, mTLS client certificates | MITM, impersonation of trusted services |
| **Encryption keys** | Data encryption keys, key encryption keys, PGP keys | Decryption of sensitive data at rest |
| **Connection strings** | Database URLs with embedded credentials, Redis URLs | Direct data access from any network path |
| **SSH keys** | Private keys for server access, deploy keys | Infrastructure compromise |
| **Environment-specific values** | HMAC secrets, hashing salts, signing secrets | Integrity bypass, hash cracking |
| **Third-party secrets** | Vendor API tokens, SIEM tokens, monitoring credentials | Pivot point into other systems |

**The golden rule:** If it's a string that gates access to anything, it's a secret. Treat it as such from the moment it's generated until the moment it's destroyed.

### What's NOT a Secret (But Often Mistaken for One)

- Public API keys (client-side SDK keys that are designed to be embedded in mobile apps) — these still need rate limiting, but exposure is not catastrophic.
- JWTs that are signed and expire in 5 minutes (but the *signing key* is a secret).
- CSRF tokens (they're one-time and session-bound — stored in app state, not as credentials).

---