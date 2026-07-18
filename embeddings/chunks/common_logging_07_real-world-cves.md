---
source: "common/logging.md"
title: "Logging & Monitoring Failures"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, logging, patterns, prevention, secure, vibe, vulnerable, what]
chunk: 7/8
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Target data breach | N/A | No monitoring of mallware on POS systems — 40M CCs stolen |
| Equifax breach | N/A | Missed logging on unpatched Struts server — 147M records |
| SolarWinds Orion | CVE-2021-35215 | Authenticated insecure deserialization → RCE in Orion Platform (CWE-502); the wider SolarWinds intrusion also featured attackers tampering with logs to evade detection |
| Capital One | N/A (no CVE) | SSRF (WAF misconfiguration) reached the AWS instance-metadata service; no alerting on the anomalous access — 100M records exfiltrated |

> **The Target breach example:** Attackers installed malware on POS systems. The security team had SIEM alerts firing, but no one was monitoring at 2 AM. 40M credit card numbers stolen over 11 days.

---