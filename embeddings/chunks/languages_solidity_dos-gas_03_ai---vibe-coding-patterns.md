---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
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
| "Distribute rewards to everyone" | `for` + `transfer` unbounded |
| "Auction refund previous" | Push refund inside `bid()`; reverting bidder DoS |
| "Delete all stakers" | Entire array in one TX |
| "Airdrop N address" | N is user-controlled, gas DoS |
| `require(success)` on every send | One bad receiver kills entire batch |

```
Prompt: "Share profits to investors"
AI:
function distribute() external {
  for (uint i; i < investors.length; i++) {
    payable(investors[i]).transfer(share); // 💀
  }
}
```

---