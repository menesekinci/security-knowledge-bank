---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Impact Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 8/11
---

## Impact Examples

| Attack Vector | What Attacker Can Do |
|---|---|
| Request smuggling | Bypass WAF/firewall rules |
| Cross-user poisoning | Poison cached pages — all users served attacker content |
| Session hijacking | Steal session cookies from other users |
| Auth bypass | Access protected endpoints by smuggling requests |
| Cache poisoning | Inject malicious content into CDN caches |

---