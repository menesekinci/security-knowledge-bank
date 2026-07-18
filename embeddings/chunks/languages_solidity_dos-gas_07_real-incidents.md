---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
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
| **GovernMental** | ~2016 | Pyramid/ponzi-style contract; large state + gas → stuck | Classic Ethereum DoS case studies / SWC-128 discussions |
| **King of the Ether Throne** | early ETH | Claim/crown transition and gas/call edge cases | Historical contract analyses |
| **Various ICO refund loops** | 2017–18 | Push refund on investor list → gas limit | Industry audits (class pattern) |
| **Auction griefing (generic)** | continuous | Reverting bidder / smart contract wallet edge | SWC-128, ConsenSys best practices |

Refs: [SWC-128](https://swcregistry.io/docs/SWC-128), [ConsenSys — DoS](https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/).

---