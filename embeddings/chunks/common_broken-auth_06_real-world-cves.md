---
source: "common/broken-auth.md"
title: "Broken Authentication & Session Management"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common, common-vuln, cves, prevention, real-world, vibe, vulnerabilities, what]
chunk: 6/7
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| JWT algorithm confusion / `alg:none` (jsonwebtoken) | CVE-2015-9235 | Signature accepted from token header → forged tokens (public key as HMAC secret) |
| Apache Tomcat session-persistence deserialization | CVE-2020-9484 | RCE via `PersistenceManager` + `FileStore` deserialization (not session fixation) |
| Drupal Form API property injection (Drupalgeddon2) | CVE-2018-7600 | Unauthenticated remote code execution (CVSS 9.8) |
| Spring Security WebFlux `**` pattern mismatch | CVE-2023-34034 | Authorization bypass — security rules skipped (not a JWT flaw) |
| Hard-coded JWT secret (MICROSENS NMP Web+) | CVE-2025-49151 | Unauthenticated JWT forgery → authentication bypass (CVSS 9.1) |
| Pulse Connect Secure VPN arbitrary file read | CVE-2019-11510 | Unauthenticated leak of session tokens & plaintext credentials (CVSS 10.0), mass-exploited |

---