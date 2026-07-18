---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 9/10
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Atlassian Jira SSRF (`makeRequest` gadget) | CVE-2019-8451 | Unauthenticated access to internal network resources |
| Grafana avatar SSRF | CVE-2020-13379 | Unauthenticated server makes HTTP requests to any URL |
| Apache Solr SSRF (`masterUrl` replication) | CVE-2021-27905 | Reach internal services via replication handler |
| MinIO SSRF | CVE-2021-21287 | AWS metadata / internal database access |
| GitLab webhook SSRF | CVE-2021-22214 | Unauthenticated requests to arbitrary internal domains |
| Capital One breach (EC2 metadata SSRF) | N/A (WAF misconfiguration incident / no single CVE) | 100M+ records exposed via IMDS credential theft |

---