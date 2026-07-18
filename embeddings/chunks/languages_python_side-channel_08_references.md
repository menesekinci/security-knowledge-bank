---
source: "languages/python/side-channel.md"
title: "Side-Channel Risks in Python"
heading: "References"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [additional, cve-2021-23336, cve-2023-50782, cve-2024-23342, language-vuln, overview, python, python-cryptography, python-ecdsa]
chunk: 8/8
---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2023-50782 — python-cryptography Bleichenbacher/Marvin padding-timing oracle
2. https://github.com/advisories/GHSA-3ww4-gg4f-jr7f — python-cryptography advisory (CVE-2023-50782)
3. https://nvd.nist.gov/vuln/detail/CVE-2024-23342 — python-ecdsa Minerva P-256 timing side-channel
4. https://nvd.nist.gov/vuln/detail/CVE-2021-23336 — Python urllib parameter cloaking / web cache poisoning
5. https://robotattack.org/ — The ROBOT attack (Bleichenbacher oracle)
6. https://people.redhat.com/~hkario/marvin/ — The Marvin Attack
7. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle — OWASP padding oracle testing