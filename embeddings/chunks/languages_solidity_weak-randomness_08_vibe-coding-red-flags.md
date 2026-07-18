---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 block.timestamp % n
🚩 keccak256(block.timestamp, msg.sender, ...)
🚩 blockhash(block.number - 1) with payout in same function
🚩 "difficulty/prevrandao is sufficient" for high TVL gambling
🚩 AI: "blockchain random is secure"
🚩 User guess + resolve in single TX
🚩 Secret seed in plain contract storage
🚩 msg.sender as sole entropy
```

### AI Prompt Snippet

```
Don't use block.timestamp/blockhash for on-chain gambling/lottery/NFT rarity.
High value: Chainlink VRF (separate request/fulfill).
Medium: commit-reveal + multi-party seed.
Don't allow predict-and-win in the same transaction.
```

---

**Severity: 🟠 High** — Protocol vault can be systematically drained.
**SWC: SWC-120** · **Refs:** [SWC-120](https://swcregistry.io/docs/SWC-120), [ConsenSys — randomness](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/randomness/), [Chainlink VRF docs](https://docs.chain.link/vrf)