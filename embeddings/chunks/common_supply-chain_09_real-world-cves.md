---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 9/10
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| SolarWinds Orion backdoor (SUNBURST) | N/A (malicious build injection / no classic CVE) | Supply chain RCE — ~18K orgs |
| Codecov Bash Uploader | N/A (compromised CI script / no CVE) | Credential/env-var exfiltration from CI |
| UA-Parser-JS cryptominer | N/A (malicious package / hijacked maintainer account) | Cryptominer in a 7M+ weekly-download package |
| event-stream / flatmap-stream | N/A (malicious package) | Bitcoin wallet theft |
| colors.js / faker.js sabotage | N/A (maintainer self-sabotage / no CVE) | Breaking change to thousands of apps |
| XZ Utils / liblzma backdoor | CVE-2024-3094 | Hidden backdoor injected into build; enabled SSH compromise |
| log4j JNDI injection (Log4Shell) | CVE-2021-44228 | RCE via vulnerable logging dependency |

---