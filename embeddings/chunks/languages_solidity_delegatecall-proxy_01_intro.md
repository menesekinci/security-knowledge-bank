---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 1/8
---

# 🟡 Delegatecall & Proxy Storage Risks

| Field | Value |
|-------|-------|
| **Severity** | 🔴 Critical (storage corruption / full takeover) |
| **SWC** | [SWC-112](https://swcregistry.io/docs/SWC-112) — Delegatecall to Untrusted Callee |
| **CWE** | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Inclusion of Functionality from Untrusted Control Sphere |
| **Related** | [access-control.md](access-control.md), [reentrancy.md](reentrancy.md), [unchecked-calls.md](unchecked-calls.md), case: [wormhole-bridge-2022](case-studies/wormhole-bridge-2022-signature-bypass.md) |

---