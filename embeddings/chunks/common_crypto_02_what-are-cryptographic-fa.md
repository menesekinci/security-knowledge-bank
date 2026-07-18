---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "What Are Cryptographic Failures?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 2/9
---

## What Are Cryptographic Failures?

Cryptographic failures occur when applications **fail to properly protect sensitive data** through encryption, hashing, or random number generation. This includes using weak algorithms, hardcoding keys, generating predictable random values, and improperly storing passwords.

**The impact:** Sensitive data exposure, credential theft, session hijacking, man-in-the-middle attacks, and complete loss of data confidentiality/integrity.