---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Cryptographic Algorithm Comparison"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 5/9
---

## Cryptographic Algorithm Comparison

| Algorithm | Strength | Use For | Do NOT Use For |
|---|---|---|---|
| AES-256-GCM | ✅ Strong | Data encryption at rest/in transit | Password hashing |
| ChaCha20-Poly1305 | ✅ Strong | Mobile/low-power encryption | Password hashing |
| RSA-4096 | ✅ Strong | Key exchange, digital signatures | Bulk encryption |
| ECDSA (P-256) | ✅ Strong | Digital signatures | Encryption |
| Argon2id | ✅ Strong | Password hashing | Reversible encryption |
| bcrypt | ✅ Strong | Password hashing | Reversible encryption |
| SHA-256/384/512 | ✅ Strong | Integrity verification | Password hashing (unsalted) |
| MD5 | ❌ Broken | Nothing | Everything |
| SHA1 | ❌ Broken (SHAttered) | Nothing secure | Digital signatures |
| DES/3DES | ❌ Broken | Nothing | Everything |
| RC4 | ❌ Broken | Nothing | Everything |
| AES-ECB | ❌ Broken | Nothing | Anything non-random |
| RSA-1024 | ❌ Weak | Nothing (≤1024 deprecated) | New implementations |

---