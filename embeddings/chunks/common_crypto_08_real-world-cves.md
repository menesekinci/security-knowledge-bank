---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 8/9
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Predictable SHA1PRNG `SecureRandom` (Apache Harmony / Android < 4.4) | CVE-2013-7372 | PRNG predictability enabled theft of Bitcoin wallet keys in the wild |
| Heartbleed — OpenSSL missing bounds check on Heartbeat packets | CVE-2014-0160 | Buffer over-read leaks process memory, including TLS private keys |
| SWEET32 — 64-bit block ciphers (3DES / Blowfish) birthday bound | CVE-2016-2183 | Plaintext recovery from long-lived TLS/SSH/VPN sessions |
| RC4 single-byte keystream biases in TLS/SSL | CVE-2013-2566 | Plaintext recovery via statistical analysis of many ciphertexts |
| Bleichenbacher/Marvin RSA timing oracle in python-cryptography (< 42.0.0) | CVE-2023-50782 | Decryption of captured RSA-encrypted TLS traffic (PKCS#1 v1.5 padding oracle) |
| Log4Shell — Log4j2 JNDI lookup with no endpoint restriction | CVE-2021-44228 | Unauthenticated RCE via attacker-controlled log message |
| SHA-1 collision (SHAttered) — **no CVE assigned** | N/A (SHAttered, 2017) | Colliding files / basis for forged digital signatures |

---