---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 7/9
---

## Prevention Checklist for AI Prompts

```
✅ CRYPTOGRAPHY REQUIREMENTS FOR THIS CODE:
- NEVER hardcode keys, secrets, or passwords — use environment variables or a secrets manager
- Use AES-256-GCM or ChaCha20-Poly1305 for encryption (NOT ECB, CBC without MAC, or stream ciphers)
- Use Argon2id for password hashing (fallback: bcrypt cost ≥ 12, then scrypt, then PBKDF2)
- NEVER use MD5 or SHA1 for security purposes
- Use cryptographically secure random (secrets module in Python, crypto.randomBytes in Node.js)
- Never use Math.random(), random.random(), or similar for security tokens
- Generate a unique IV/nonce for EVERY encryption operation
- Use authenticated encryption (GCM, ChaCha20-Poly1305) that provides integrity AND confidentiality
- Always verify TLS certificates — never set rejectUnauthorized=false
- Enforce HTTPS with HSTS headers
- Use minimum key sizes: AES-256, RSA-3072+, ECDSA P-256+
- Rotate keys regularly and have a key rotation procedure
```

---