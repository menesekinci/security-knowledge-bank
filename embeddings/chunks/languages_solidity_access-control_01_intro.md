---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 1/8
---

# 🟠 Access Control Vulnerabilities

| Field | Value |
|-------|-------|
| **Severity** | 🔴 Critical → 🟠 High (depending on function impact) |
| **SWC** | [SWC-105](https://swcregistry.io/docs/SWC-105) Unprotected Ether Withdrawal · [SWC-106](https://swcregistry.io/docs/SWC-106) Unprotected SELFDESTRUCT · [SWC-115](https://swcregistry.io/docs/SWC-115) tx.origin |
| **CWE** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) Improper Access Control |
| **Related** | [tx-origin.md](tx-origin.md), [delegatecall-proxy.md](delegatecall-proxy.md), [reentrancy.md](reentrancy.md), case: [poly-network-2021](case-studies/poly-network-2021-610m-hack.md) |

---