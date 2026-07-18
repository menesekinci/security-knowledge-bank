---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "What Is It? (Explanation)"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
---

## What Is It? (Explanation)

Access control answers the question **who can make which state change / fund movement**. Missing or incorrect protection:

- Anyone can call `withdraw`, `mint`, `setOwner`, `upgradeTo`, `selfdestruct`
- Wrong constructor naming (old Solidity) → init is public
- `initialize()` in proxy without `initializer` protection → attacker is first-caller owner
- `onlyOwner` forgotten on admin functions
- Auth via `tx.origin` → phishing contract ([tx-origin.md](tx-origin.md))
- Role confusion: `MINTER` and `DEFAULT_ADMIN` same wallet, or role admin chain is weak

On the blockchain, "unauthorized access" is not a web-style 403 — it is **irreversible asset transfer**.

---