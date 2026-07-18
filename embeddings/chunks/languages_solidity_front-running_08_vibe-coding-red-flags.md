---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 swap/liquidity: no minAmountOut parameter
🚩 deadline = type(uint).max or absent
🚩 "Fair launch mint" single TX, no limit
🚩 On-chain cleartext bid/secret
🚩 approve(spender, amount) single step, no permit
🚩 AI: "blockchain is ordered so front-run is impossible" — quite the opposite
🚩 Dependent trade in the same block as oracle update
```

### AI Prompt Snippet

```
Add minAmountOut/maxAmountIn and deadline to every swap and price-sensitive function.
Use commit-reveal for auctions or secret values.
Use increaseAllowance or EIP-2612 permit for ERC20 approval.
Assume MEV/sandwich scenario; mempool is public.
```

---

**Severity: 🟠 High** — Though not a direct "hack", it constantly leaks value; protocol insolvency in some designs.
**SWC: SWC-114** · **Refs:** [SWC-114](https://swcregistry.io/docs/SWC-114), [ConsenSys best practices — TOD](https://consensys.github.io/smart-contract-best-practices/attacks/front-running/), Flashbots / MEV research literature