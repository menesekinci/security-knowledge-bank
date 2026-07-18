---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "Real-World CVEs / References"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

| CVE | Vulnerability | Impact | Ref |
|-----|--------------|--------|-----|
| CVE-2008-0166 | Debian OpenSSL PRNG broken by patched-out entropy calls | SSH keys reduced to ~32768 possibilities; millions of keys compromised globally | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-0166), [Debian DSA-1571](https://www.debian.org/security/2008/dsa-1571), [badkeys.info](https://badkeys.info/docs/debian.html) |
| CVE-2013-7372 | Android `SecureRandom` incorrect offset — predictable Bitcoin wallet key generation | Bitcoin wallets on Android compromised; cryptocurrency theft | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2013-7372), [Guardian report](https://www.theguardian.com/technology/2013/aug/15/google-android-bitcoin-securerandom-vulnerability) |
| CVE-2016-10180 | D-Link DWR-932B router WPS PIN uses `srand(time(0))` | Predictable WPS PIN via epoch-time seed (CVSS 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2016-10180), [CWE-337](https://cwe.mitre.org/data/definitions/337.html) |
| CVE-2022-39218 | Fastly Compute@Edge JS runtime uses fixed random seed for WebAssembly `Math.random` | Attacker can predict random numbers to bypass cryptographic controls | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-39218) |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator | Category reference | |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) | Incorrect Usage of Seeds in Pseudo-Random Number Generator | Category reference | |

The Debian OpenSSL bug (CVE-2008-0166) remains the most devastating RNG failure in history. A single line change — commenting out `#define DEVRANDOM` — made all OpenSSL keys generated on Debian/Ubuntu systems between September 2006 and May 2008 predictable. Compromised keys are still found in the wild on IoT devices running outdated firmware, and the [badkeys](https://badkeys.info/) project maintains a database of affected keys.

---