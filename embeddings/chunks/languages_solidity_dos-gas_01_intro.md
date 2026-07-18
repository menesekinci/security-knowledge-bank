---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 1/8
---

# 🟡 Denial of Service via Gas (DoS)

| Field | Value |
|-------|-------|
| **Severity** | 🟡 Medium → 🟠 High (fund lock / governance paralysis) |
| **SWC** | [SWC-128](https://swcregistry.io/docs/SWC-128) — DoS With Block Gas Limit |
| **CWE** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption |
| **Related** | [unchecked-calls.md](unchecked-calls.md), [reentrancy.md](reentrancy.md), [front-running.md](front-running.md) |

---