---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 10/11
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Apache HTTP Server mod_proxy request splitting/smuggling | CVE-2023-25690 | Access-control bypass, cache poisoning (CVSS 9.8) |
| nginx error_page request smuggling | CVE-2019-20372 | WAF bypass, request injection |
| HAProxy integer-overflow request smuggling | CVE-2021-40346 | Bypass of `http-request` ACLs via smuggled request |
| Node.js llhttp Transfer-Encoding smuggling | CVE-2022-32215 | Cache poisoning / request smuggling via multi-line TE header |
| Apache Tomcat Ghostcat (AJP) | CVE-2020-1938 | AJP-based local file inclusion / potential RCE — an AJP protocol issue, not CL/TE HTTP smuggling |

---