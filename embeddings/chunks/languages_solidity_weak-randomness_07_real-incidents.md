---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
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
| **Fomo3D / airdrop-style PRNG** | 2018 | On-chain "random" airdrop/bonus; bots and block vars give advantage | Public analyses, SWC-120 discussions |
| **SmartBillions** | ~2017 | `blockhash`-based lottery design flaws | Historical Ethereum lottery write-ups |
| **Countless vulnerable coin-flip CTF/mainnet copies** | continuous | `keccak(timestamp)` pattern | [SWC-120](https://swcregistry.io/docs/SWC-120) samples |
| **NFT mint trait sniping** | 2021+ | Predictable rarity at mint | Industry reports (class pattern) |

---