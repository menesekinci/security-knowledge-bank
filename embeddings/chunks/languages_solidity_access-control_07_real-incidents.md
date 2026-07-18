---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "Real Incidents"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 7/8
---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Parity multi-sig #1** | 2017 | `initWallet`-like init was public → attacker becomes owner | Parity post-mortem / industry reports |
| **Parity library freeze** | 2017 | `killed` / ownership in library → `selfdestruct` → ~500k+ ETH locked | SWC-106 class, public post-mortems |
| **Rubixi** | ~2016 | Wrong constructor name → creator hijack | [SWC-105 Rubixi](https://swcregistry.io/docs/SWC-105) |
| **Poly Network** | 2021 | Cross-chain / keeper authority design → ~$610M (most returned) | [case-studies/poly-network-2021-610m-hack.md](case-studies/poly-network-2021-610m-hack.md) |
| **The DAO (2016)** | 2016 | Primary vector was reentrancy; org/governance trust model also broken | [dao-hack-2016-reentrancy.md](case-studies/dao-hack-2016-reentrancy.md), [reentrancy.md](reentrancy.md) |

---