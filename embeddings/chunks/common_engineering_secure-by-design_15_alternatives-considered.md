---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "Alternatives Considered"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 15/25
---

## Alternatives Considered
| Alternative | Why Rejected |
|---|---|
| Session cookies with server-side sessions | Requires stateful session store; horizontal scaling complexity |
| API keys | No user identity binding; key rotation is manual |
| Mutual TLS | Operational complexity beyond current team capacity; not yet supported by clients |