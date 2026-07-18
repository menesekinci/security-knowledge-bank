---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
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
| "Write a DEX swap" | No slippage / deadline → sandwich |
| "NFT mint, first-come" | No commit-reveal; bot mint |
| "Liquidation function" | Public race; MEV liquidation |
| "Buy at oracle price" | Oracle update + trade visible in mempool |
| "Sealed bid auction" | Single TX bid on-chain and visible |

```
Prompt: "Uniswap-like swap"
AI:
function swap(address tokenIn, address tokenOut, uint amountIn) external {
    uint out = getAmountOut(amountIn); // 💀 no minOut
    // transfer...
}
```

---