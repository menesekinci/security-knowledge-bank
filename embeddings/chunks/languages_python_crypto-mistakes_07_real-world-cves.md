---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2013-1445** | PyCrypto ≤2.6 — `Crypto.Random` PRNG not reseeded after `os.fork()`, so a child reuses the parent's random state | Predictable keys/tokens across processes |
| **CVE-2018-6594** | PyCrypto/pycryptodome — weak ElGamal key generation (generator is not a quadratic residue, breaking the DDH assumption) | Ciphertext recoverable; no semantic security |
| **CVE-2022-29217** | PyJWT <2.4.0 — algorithm/key confusion: a public key can be accepted as an HMAC secret when `algorithms` is unspecified | JWT forgery / auth bypass |
| **CVE-2020-36242** | python-cryptography <3.3.2 — integer overflow → buffer overflow when symmetrically encrypting multi-GB values (e.g. via `Fernet`) | Memory corruption / crash |
| **CVE-2020-13757** | python-rsa <4.1 — PKCS#1 v1.5 decryption/verification ignores prepended `\0` bytes (padding length not validated) | Ciphertext/signature malleability, info disclosure |

---