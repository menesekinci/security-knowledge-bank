---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
heading: "Real-World CVEs"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [checklist, code, cves, explanation, javascript, language-vuln, prevention, real-world, secure, vulnerability]
chunk: 6/7
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2023-46233** | `crypto-js` < 4.2.0 — default PBKDF2 uses SHA-1 with a single iteration (~1000x weaker than spec) | Weak key derivation; brute-forceable hashes (CVSS 9.1; fixed 4.2.0) |
| **CVE-2023-46234** | `browserify-sign` 2.6.0–4.2.1 — upper-bound check flaw in `dsaVerify` lets any public key verify crafted signatures | Signature forgery (CVSS 7.5; fixed 4.2.2) |
| **CVE-2022-24771** | `node-forge` < 1.3.0 — RSA PKCS#1 v1.5 signature verification too lenient on the digest structure | Signature forgery with low public exponent (fixed 1.3.0) |
| **CVE-2018-1000620** | `cryptiles` <= 4.1.1 — `randomDigits()` biased / insufficient entropy (CWE-331) | Predictable "random" security tokens (fixed 4.1.2) |

---