---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "AI / Vibe Coding Patterns"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 3/8
---

## AI / Vibe Coding Patterns

| Prompt | AI Mistake |
|--------|------------|
| "Write an upgradeable ERC20" | No storage gap; V2 new variable at slot 0 |
| "Use proxy" | `delegatecall` to `msg.sender` or user input address |
| "Initialize owner" | No `initialized` in implementation; attacker inits |
| "Simple proxy" | Fallback delegatecall, no admin separation |
| "Copy OZ" | Old OZ, missing `_disableInitializers` |

```
Prompt: "Execute logic with the library address provided by user"
AI:
function execute(address lib, bytes calldata data) external {
  lib.delegatecall(data); // 💀 SWC-112
}
```

---