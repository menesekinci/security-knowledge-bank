---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "AI / Vibe Coding Patterns"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 3/8
---

## AI / Vibe Coding Patterns

Dangerous patterns commonly produced by AI:

| Prompt / context | AI behavior | Risk |
|-----------------|-------------|------|
| "Write token mint/burn" | `balances[to] += amount` (0.7 pragma or unchecked) | Mint explosion |
| "Optimize gas" | Wraps all arithmetic in `unchecked` | SWC-101 returns |
| "Batch transfer" | `cnt * value` unchecked multiplication | BEC-style wrap |
| "We're using 0.8 so it's safe" | `unchecked` + assembly forgotten | False sense of security |
| "Price × quantity" | Order / scale error | Precision loss, free tokens |

```
Prompt: "Write ERC20 batchTransfer, make gas cheap"
AI: unchecked { uint amount = cnt * value; ... }  // 💀
```

---