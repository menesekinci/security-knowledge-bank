---
source: "languages/python/timing-attacks.md"
title: "Timing Attack Vectors in Python"
heading: "References"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [cve-2020-25659, cve-2023-50782, cve-2024-23342, general, language-vuln, overview, python, python-cryptography, python-ecdsa, vulnerable]
chunk: 8/8
---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2023-50782 — python-cryptography Bleichenbacher/Marvin RSA timing oracle
2. https://nvd.nist.gov/vuln/detail/CVE-2020-25659 — python-cryptography Bleichenbacher RSA decryption timing
3. https://nvd.nist.gov/vuln/detail/CVE-2024-23342 — python-ecdsa Minerva P-256 nonce timing attack
4. https://sqreen.github.io/DevelopersSecurityBestPractices/timing-attack/python — Timing attacks against Python string comparison
5. https://docs.python.org/3/library/hmac.html#hmac.compare_digest — Python docs for compare_digest
6. https://codahale.com/a-lesson-in-timing-attacks/ — Classic timing attack primer
7. https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy — Double HMAC strategy