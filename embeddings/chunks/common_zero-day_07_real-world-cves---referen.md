---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "Real-World CVEs / References"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

### Log4Shell — n-day mass exploitation after disclosure

- **[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)** — Apache Log4j2 JNDI injection (Log4Shell). Once public, global scanning and mass exploitation demonstrated classic **patch lag**: many organizations needed days to weeks to inventory transitive Java dependencies and redeploy. Follow-on issues ([CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046), [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/CVE-2021-45105)) showed incomplete first patches and the cost of partial mitigations.

### MOVEit — mass exploitation of a high-impact file-transfer flaw

- **[CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362)** — Progress MOVEit Transfer SQL injection leading to widespread data theft campaigns. Illustrates how a single product 0-day/n-day cycle becomes **supply-chain-like impact** for hundreds of organizations depending on one appliance/vendor update pipeline.

### Memory-safety n-days that defined industry response

- **[CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)** — Heartbleed (OpenSSL): long patch lag across appliances and forgotten OpenSSL embeds.
- **[CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235)** — GHOST (glibc `gethostbyname`): libc-level n-day requiring full host rebuilds.
- **[CVE-2015-7547](https://nvd.nist.gov/vuln/detail/CVE-2015-7547)** — glibc `getaddrinfo` stack-based buffer overflow: again, OS/vendor lag.
- **[CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156)** — Baron Samedit (sudo heap overflow): privilege escalation n-day on countless Linux fleets.

### Standards and catalogs

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — prioritize actively exploited n-days  
- [OWASP Dependency-Check / SCA guidance](https://owasp.org/www-community/Component_Analysis)  
- [NVD](https://nvd.nist.gov/) / [OSV](https://osv.dev/) for version-level vulnerability data  

---