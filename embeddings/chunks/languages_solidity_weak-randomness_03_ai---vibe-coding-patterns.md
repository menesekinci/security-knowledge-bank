---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "AI / Vibe Coding Patterns"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 3/8
---

## AI / Vibe Coding Patterns

| Prompt | AI error |
|--------|----------|
| "Lottery random winner" | `uint(keccak(block.timestamp)) % n` |
| "NFT random rarity" | `blockhash` at mint time |
| "Coin flip bet" | Randomness + payout in the same TX |
| "Shuffle array" | On-chain pseudo-random seed weak |
| "Secure random with difficulty" | `prevrandao` alone insufficient for gambling |

```
Prompt: "Simple coinflip dapp"
AI:
function flip() external payable {
  require(msg.value == 1 ether);
  if (uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2 == 0) {
    payable(msg.sender).transfer(2 ether); // 💀 predict + only win
  }
}
```

---