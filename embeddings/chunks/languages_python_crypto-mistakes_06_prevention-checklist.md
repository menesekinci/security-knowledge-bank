---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] NEVER use `random` module for security tokens, passwords, keys — use `secrets`
- [ ] NEVER use MD5 or SHA-1 for security purposes (integrity only, not passwords)
- [ ] Use `bcrypt`, `argon2`, or `scrypt` for password hashing (not plain SHA)
- [ ] Use `Fernet` for simple symmetric encryption (handles IV, auth, padding)
- [ ] Use AES-GCM or ChaCha20-Poly1305 for custom encryption (authenticated modes)
- [ ] NEVER hardcode keys/IVs — use environment variables or a KMS
- [ ] ALWAYS generate a new random IV for each encryption call
- [ ] Use `hmac.compare_digest()` for signature/token comparison
- [ ] Use `secrets.token_hex()`, `secrets.token_urlsafe()`, `secrets.randbelow()`
- [ ] Use `hashlib.pbkdf2_hmac()` if you must derive keys from passwords
- [ ] Keep key sizes at industry standards: AES-128/256, RSA-2048+, ECC P-256+

---