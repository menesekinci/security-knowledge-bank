---
source: "languages/python/ssrf-python.md"
title: "Python-Specific SSRF Patterns"
heading: "References"
category: "language-vuln"
language: "python"
severity: "high"
tags: [aiohttp, cve-2024-35195, cve-2024-37891, cve-2025-53643, language-vuln, overview, python, requests, ssrf, urllib3]
chunk: 8/8
---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2024-35195 — requests session cert bypass
2. https://nvd.nist.gov/vuln/detail/CVE-2024-37891 — urllib3 proxy SSRF
3. https://nvd.nist.gov/vuln/detail/CVE-2025-53643 — aiohttp request smuggling
4. https://www.sentinelone.com/vulnerability-database/cve-2025-0938/ — Python URL parser differential
5. https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56 — requests advisory
6. https://github.com/aio-libs/aiohttp/security/advisories/GHSA-45c4-8wx5-qw6w — aiohttp advisory
7. https://github.com/Kozea/WeasyPrint/security/advisories/GHSA-983w-rhvv-gwmv — WeasyPrint SSRF via urllib