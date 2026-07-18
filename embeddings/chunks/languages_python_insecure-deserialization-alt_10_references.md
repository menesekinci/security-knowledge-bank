---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "References"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 10/10
---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2026-24009 — Docling PyYAML RCE
2. https://nvd.nist.gov/vuln/detail/CVE-2020-14343 — PyYAML FullLoader bypass
3. https://nvd.nist.gov/vuln/detail/CVE-2020-1747 — PyYAML original RCE
4. https://nvd.nist.gov/vuln/detail/CVE-2021-23410 — msgpack DoS
5. https://nvd.nist.gov/vuln/detail/CVE-2026-21452 — msgpack DoS via models
6. https://www.sourcery.ai/vulnerabilities/python-lang-security-deserialization-avoid-jsonpickle — jsonpickle warning
7. https://www.oligo.security/blog/docling-rce-a-shadow-vulnerability-introduced-via-pyyaml-cve-2026-24009 — Oligo's CVE-2026-24009 deep dive
8. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md — Payloads All The Things