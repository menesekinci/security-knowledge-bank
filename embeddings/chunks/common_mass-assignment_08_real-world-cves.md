---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 8/9
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Ruby on Rails — `attr_protected` bypass | CVE-2013-0276 | Crafted request modifies protected model attributes (mass assignment) — CVSS 4.3 (v2) |
| Ruby on Rails — Strong Parameters bypass via `create_with` | CVE-2014-3514 | Active Record `create_with` circumvents strong-parameter allowlists — CVSS 7.5 (v2) |
| Spring Framework — `class.classLoader` data binding | CVE-2010-1622 | Property binding reaches the class loader → arbitrary code execution — CVSS 6.0 (v2) |
| Spring Framework — "Spring4Shell" data binding | CVE-2022-22965 | Unsafe request-parameter binding reaches the class loader → RCE — CVSS 9.8 (v3.1) |
| Grails framework — data binding to class loader | CVE-2022-35912 | Data binding traverses to the class loader → RCE — CVSS 9.8 (v3.1) |

---