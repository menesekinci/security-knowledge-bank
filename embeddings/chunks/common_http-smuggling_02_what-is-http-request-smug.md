---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "What Is HTTP Request Smuggling?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 2/11
---

## What Is HTTP Request Smuggling?

HTTP Request Smuggling exploits **differences in how front-end servers (proxies, load balancers, CDNs) and back-end servers parse HTTP requests**. Attackers craft ambiguous requests that the front-end interprets as one request but the back-end interprets as multiple requests. This "smuggles" a malicious second request past security controls.

**The impact:** Session hijacking, authentication bypass, cross-user request poisoning, cache poisoning, firewall bypass.