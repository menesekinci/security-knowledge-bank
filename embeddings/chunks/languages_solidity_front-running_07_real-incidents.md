---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "Real Incidents"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 7/8
---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Bancor front-running discussions** | 2017 | Bot front-running discussions on early DEX/on-chain market | Public security discussions / SWC-114 context |
| **Uniswap/Sushiswap sandwich industry** | 2020+ | MEV bot ecosystem; user slippage loss (not a single "CVE", systemic) | Flashbots research, academic MEV papers |
| **NFT mint sniping** | 2021– | Public mint TXs front-run by bots | Widespread incident class |
| **Liquidation MEV** | DeFi continuous | Race liquidation in lending protocols | Protocol post-mortems (Compound/Aave-class dynamics) |

SWC Registry: [SWC-114 Transaction Order Dependence](https://swcregistry.io/docs/SWC-114).  
The DAO (2016) was primarily reentrancy; don't confuse with ordering discussions — [reentrancy.md](reentrancy.md), [dao-hack-2016](case-studies/dao-hack-2016-reentrancy.md).

---