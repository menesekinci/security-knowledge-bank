---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
heading: "Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [checklist, code, cves, explanation, javascript, language-vuln, prevention, real-world, secure, vulnerability]
chunk: 5/7
---

## Prevention Checklist

- [ ] NEVER use `Math.random()` for security purposes (tokens, passwords, keys, session IDs)
- [ ] Use `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` (Node.js)
- [ ] Use `bcrypt` or `argon2` for password hashing — never use plain `hashlib`
- [ ] Use AES-GCM or ChaCha20-Poly1305 for encryption (authenticated modes)
- [ ] Never use ECB mode (leaks patterns), never use CBC without HMAC (tampering)
- [ ] Always generate a new random IV/salt for each encryption operation
- [ ] Use PBKDF2/Argon2/scrypt for key derivation from passwords, never raw keys
- [ ] Use `crypto.timingSafeEqual()` for all HMAC/signature comparison
- [ ] Keep key sizes: AES-128/256, RSA-2048+, ECC P-256+
- [ ] Use SubtleCrypto API properly with correct algorithm names

---