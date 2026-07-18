---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "Consequences"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 16/25
---

## Consequences
+ Short-lived tokens limit the blast radius of token theft
+ Stateless — no session DB to scale or secure
− Token revocation requires a deny-list (short TTL mitigates this)
− JWT library must be kept up to date (critical for alg confusion attacks)