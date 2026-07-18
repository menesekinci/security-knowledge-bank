---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 1/8
---

# 🟠 Front-Running & MEV

| Field | Value |
|-------|-------|
| **Severity** | 🟠 High (value extraction / unfair ordering) |
| **SWC** | [SWC-114](https://swcregistry.io/docs/SWC-114) — Transaction Order Dependence |
| **CWE** | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource |
| **Related** | [flash-loan.md](flash-loan.md), [oracle-manipulation.md](oracle-manipulation.md), [reentrancy.md](reentrancy.md) |

---