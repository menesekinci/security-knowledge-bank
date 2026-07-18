---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [checklist, code, cves, explanation, javascript, language-vuln, prevention, real-world, secure, vulnerability]
chunk: 7/7
---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
Math.random() used for tokens/keys    // 💥 Predictable PRNG
crypto.createHash('md5') for passwords  // 💥 Broken hash
crypto.createHash('sha1') for passwords // 💥 Deprecated hash
btoa(string) for "encryption"          // 💥 Base64 != encryption
xor cipher implementation              // 💥 Roll-your-own crypto
static iv = [...]                      // 💥 Reused initialization vector
ecb mode encryption                    // 💥 ECB is deterministic
```

> **Golden Rule:** If AI-generated JavaScript uses `Math.random()` for anything security-related, it's a vulnerability. If it implements custom XOR/base64/"encryption", it's a vulnerability.