---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 1/8
---

# 🟠 Integer Overflow / Underflow

| Field | Value |
|-------|-------|
| **Severity** | 🟠 High (drops with 0.8+ default check; critical again with `unchecked`) |
| **SWC** | [SWC-101](https://swcregistry.io/docs/SWC-101) — Integer Overflow and Underflow |
| **CWE** | [CWE-190](https://cwe.mitre.org/data/definitions/190.html) / [CWE-191](https://cwe.mitre.org/data/definitions/191.html) / [CWE-682](https://cwe.mitre.org/data/definitions/682.html) |
| **Related** | [reentrancy.md](reentrancy.md), [flash-loan.md](flash-loan.md), [unchecked-calls.md](unchecked-calls.md) |

---