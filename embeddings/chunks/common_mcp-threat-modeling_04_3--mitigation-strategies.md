---
source: "common/mcp-threat-modeling.md"
title: "MCP Threat Modeling"
heading: "3. Mitigation Strategies per Threat"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [architecture, categories, common-vuln, incident, mitigation, references, response, strategies, threat]
chunk: 4/6
---

## 3. Mitigation Strategies per Threat

| Threat | Mitigation | Priority |
|--------|------------|----------|
| **T1: Tool Poisoning** | Pin tool versions, sign schemas, scan descriptions for hidden instructions, monitor for description drift | **Critical** |
| **T2: Prompt Injection via Tool Output** | Treat all tool output as untrusted, use context isolation (spotlighting), require human approval for sensitive actions | **Critical** |
| **T3: Context Over-Sharing** | Scope context per task/user, use ephemeral memory, enforce cross-tenant isolation at protocol layer | **High** |
| **T4: Credential Harvesting** | Short-lived OAuth 2.1 tokens with PKCE, secrets scanning, never expose secrets in tool arguments | **Critical** |
| **T5: Supply Chain** | AIBOM, signed releases, SCA on install, verified publishers, monitor CVE feeds | **High** |
| **T6: Denial of Service** | Recursion limits, timeouts, rate limiting, budget caps, call-depth monitoring | **Medium** |
| **T7: Sampling Attacks** | Sampling quotas, user approval gates, compute budget caps | **High** |

---