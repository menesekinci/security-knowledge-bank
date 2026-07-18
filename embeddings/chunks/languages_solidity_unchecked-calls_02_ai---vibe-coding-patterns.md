---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "AI / Vibe Coding Patterns"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 2/7
---

## AI / Vibe Coding Patterns

| Prompt | AI mistake |
|--------|-----------|
| "Send ETH" | `addr.send(amount);` return ignored |
| "Send flexibly with call" | `(bool ok,) = call;` `ok` unused |
| "ERC20 withdraw" | `IERC20.transfer` incompatible with USDT |
| "Low-level optimize" | success ignored + state update |
| "Forgot try/catch" | External contract call exception swallowed |

```
Prompt: "Pay the user"
AI:
balances[msg.sender] = 0;
msg.sender.send(amount); // 💀 balance is 0 even if it fails
```

---