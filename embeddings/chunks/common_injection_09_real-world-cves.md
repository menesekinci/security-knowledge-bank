---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 9/11
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| SQLi in Progress MOVEit Transfer | CVE-2023-34362 | Mass data exfiltration (Cl0p ransomware campaign) |
| NoSQLi / access-control bypass in Mongoose | CVE-2019-17426 | Query filter bypass → unauthenticated data access |
| JNDI / expression injection in Log4j (Log4Shell) | CVE-2021-44228 | RCE via JNDI lookup in log messages (not OS command injection) |
| EL Injection in Spring | CVE-2022-22965 (Spring4Shell) | Remote code execution |
| SQLi in WordPress core (`WP_Query`) | CVE-2022-21661 | Unauthenticated disclosure of database contents |

---