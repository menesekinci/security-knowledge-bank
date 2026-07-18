---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "What Is It? (Explanation)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
---

## What Is It? (Explanation)

Transactions waiting in the mempool on Ethereum (and most L1/L2s) are **visible to everyone**. Block producers / search bots can select the order of transactions or insert their own.

**Front-running:** Seeing a user TX and placing **your own TX before it**.  
**Back-running:** Placing right **after** a user TX.  
**Sandwich:** Before + after → squeezing the user via slippage on AMM.  
**MEV (Maximal Extractable Value):** Value extracted through ordering, insertion, censorship (tip, sandwich, liquidation race, arbitrage).

SWC-114 **transaction order dependence**: if contract logic is sensitive to the order of TXs in the same block, an attacker can turn the order to their advantage.

This is as much a **design constraint** as a "bug": blockchain is atomic and ordered; naive "first come wins" and "visible price quote" models are exposed to MEV.

---