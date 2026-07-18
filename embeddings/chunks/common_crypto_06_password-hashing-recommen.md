---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Password Hashing Recommendations"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 6/9
---

## Password Hashing Recommendations

| Algorithm | Work Factor | Memory | Parallelism | Notes |
|---|---|---|---|---|
| **Argon2id** | t=3, m=64MB | ✅ High | ✅ Yes | PHC winner, best option |
| **bcrypt** | cost=12 | 🟡 Low | ❌ No | Good, widely available |
| **scrypt** | N=2^16, r=8, p=1 | ✅ High | ❌ Limited | Good alternative |
| **PBKDF2** | 310,000 iterations | ❌ Low | ❌ No | Baseline, GPU-resistant |

---