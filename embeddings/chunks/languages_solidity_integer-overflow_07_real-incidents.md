---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
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
| **BeautyChain (BEC)** | 2018 | `cnt * value` overflow in `batchTransfer` → massive mint/transfer | [SWC-101 BEC sample](https://swcregistry.io/docs/SWC-101), media post-mortems |
| **SmartMesh (SMT) / similar token bugs** | 2018 | Supply corruption via ERC20 arithmetic overflow | Industry write-ups (SWC-101 class) |
| **Capture the Ether — Token Sale** | educational | `numTokens * PRICE` overflow for cheap purchase | [SWC-101](https://swcregistry.io/docs/SWC-101) |

Note: After Solidity 0.8, "classic" wrapping has decreased; modern risk is the **`unchecked` + wrong formula + assembly** triad. Amounts amplified by flash loans can trigger overflow/precision edges → [flash-loan.md](flash-loan.md).

---