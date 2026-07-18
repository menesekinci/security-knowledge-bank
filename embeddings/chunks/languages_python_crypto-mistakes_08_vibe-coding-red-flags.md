---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
random.choice(...) for tokens          # 💥 Not cryptographic
random.shuffle(...) for security       # 💥 Predictable
random.getrandbits(...)                # 💥 Mersenne Twister
hashlib.md5(...) for passwords         # 💥 Broken hash
hashlib.sha1(...) for passwords        # 💥 Deprecated hash
bytes(key, 'utf-8') for crypto        # 💥 Wrong key encoding
ecb = modes.ECB()                      # 💥 ECB mode leaks patterns
iv = b'\x00' * 16                      # 💥 Static IV
cipher = ... + ...  (custom)           # 💥 Roll-your-own crypto
```

> **Golden Rule:** Any use of `random` for security purposes is automatically a vulnerability. Any use of MD5/SHA1 for passwords is a vulnerability. Any custom encryption implementation is a vulnerability.