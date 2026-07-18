---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 7/8
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| lodash `defaultsDeep` prototype pollution | CVE-2019-10744 | `Object.prototype` pollution (CVSS 9.1) — integrity/availability impact |
| lodash `zipObjectDeep` prototype pollution | CVE-2020-8203 | `Object.prototype` pollution (CVSS 7.4) |
| json5 `parse()` prototype pollution | CVE-2022-46175 | Pollution via `__proto__` in parsed object → XSS/privesc/DoS |
| json-schema prototype pollution | CVE-2021-3918 | Prototype pollution (CVSS 9.8) |
| Kibana (Timelion) prototype pollution | CVE-2019-7609 | RCE — attacker could execute commands |

> **The Kibana case (CVE-2019-7609):** Attackers exploited prototype pollution in Kibana's Timelion visualizer to reach a code-evaluation path, achieving remote code execution on Elastic Stack deployments (CVSS 10.0).

---