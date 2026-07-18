---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] `for` + `recipients.length` / `users.length` grep — is there a bound?
- [ ] Payment: is it pull model?
- [ ] Auction/refund: no push
- [ ] Max length on batch functions
- [ ] Worst-case gas estimate (full array, hostile receiver)
- [ ] Griefing test: reverting receiver contract
- [ ] Governance execute: large operations timelock + split
- [ ] Slither `arbitrary-send-eth`, loops heuristics

---