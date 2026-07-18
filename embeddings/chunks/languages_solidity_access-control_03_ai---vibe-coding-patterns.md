---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "AI / Vibe Coding Patterns"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 3/8
---

## AI / Vibe Coding Patterns

| Prompt | AI's typical mistake |
|--------|----------------------|
| "Write a simple vault" | `withdrawAll` is public, no owner check |
| "Add Ownable" | Custom `owner` + `onlyOwner` halfway; `transferOwnership` missing/unsafe |
| "Upgradeable contract" | `initialize` is public, `initializer` modifier missing |
| "Admin pause/mint" | Modifier forgotten or only in comments |
| "Like multi-sig" | Single EOA owner; or anyone can `addOwner` |
| "tx.origin safer" | AI sometimes generates `tx.origin` which is vulnerable to phishing |

```
Prompt: "Owner should be able to withdraw funds, users should deposit"
AI:
function withdraw() public {  // 💀 no onlyOwner
    payable(owner).transfer(address(this).balance);
}
```

---