---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 8/9
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Kibana Console arbitrary code execution | CVE-2018-17246 | Local file inclusion / RCE via the Console plugin (Kibana < 6.4.3 / < 5.6.13) |
| MongoDB no auth by default | N/A (misconfiguration, no CVE) | Massive ransomware attacks against internet-exposed, auth-less instances |
| Apache Struts dev mode | CVE-2017-5638 | RCE (Equifax breach) |
| Kubernetes Dashboard auth bypass | CVE-2018-18264 | Reads cluster secrets via the Dashboard service account (Dashboard < 1.10.1) |

---