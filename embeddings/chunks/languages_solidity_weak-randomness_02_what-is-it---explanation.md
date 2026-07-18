---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "What Is It? (Explanation)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
---

## What Is It? (Explanation)

The EVM **does not provide a secure random number generator**. The following are **predictable** or **manipulatable**:

| Source | Why weak? |
|--------|-----------|
| `block.timestamp` | Miner/builder can set it within a limited range; everyone can see it |
| `block.number` | Known, changes slowly |
| `blockhash(block.number - 1)` | Past hash is public; last 256 blocks; miner influence |
| `block.prevrandao` (old `difficulty`) | Beacon random; uses **validator** info but every contract in the **same block** sees the same value; commit + predict/snipe scenarios still a design risk |
| `keccak256(abi.encodePacked(msg.sender, tx.gasprice, ...))` | Attacker controls inputs |
| `blockhash(future)` | `blockhash` only past; future = 0 |

Result: lottery, card shuffle, NFT trait, random winner, "50% chance drop" can be **biased by the attacker**. Attacker:

1. Finds winning TX via simulation (eth_call / local fork),
2. Only broadcasts profitable TXs,
3. Or cancels losing attempts via `revert` in their contract,
4. Selects order via MEV ([front-running.md](front-running.md)).

---