---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 9/10
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Apache Struts2 Jakarta Multipart OGNL injection | CVE-2017-5638 (Equifax breach) | RCE via crafted `Content-Type` header — OGNL injection, not object deserialization |
| Oracle WebLogic wls9-async / wls-wsat deserialization | CVE-2019-2725 | Unauthenticated RCE via `XMLDecoder` in the async component (not the T3 protocol) |
| Jackson-databind polymorphic deserialization | CVE-2019-12384 | RCE via polymorphic typing |
| Jenkins XStream API deserialization | CVE-2016-0792 | RCE via crafted serialized XML to API endpoints (XStream, not the CLI) |
| Apache Struts2 REST plugin XStream deserialization | CVE-2017-9805 | Unauthenticated RCE via XML payload (no type filtering) |
| PyYAML deserialization | CVE-2020-14343 | RCE via default YAML loader |
| Drupal REST deserialization | CVE-2019-6340 | RCE — SA-CORE-2019-003 |

---