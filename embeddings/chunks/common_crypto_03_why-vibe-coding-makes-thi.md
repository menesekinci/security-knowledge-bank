---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

AI code generators are particularly bad at cryptography because:

- **AI optimizes for "it works" not "it's secure":** Weak ciphers like DES, RC4, and ECB mode "work" but are insecure
- **AI selects the fastest hash:** MD5 and SHA1 are fast and commonly found in training data
- **Hardcoded secrets are in training data:** AI has seen millions of code snippets with `SECRET_KEY = "changeme"`
- **AI doesn't know about forward secrecy, nonce reuse, or padding oracle attacks**
- **AI generates `random()` for security:** Uses `Math.random()` or `random.randint()` instead of cryptographically secure RNG

---