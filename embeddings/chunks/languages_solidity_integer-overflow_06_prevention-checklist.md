---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] Compiler `^0.8.0` or above; `optimizer` + solc version locked
- [ ] Grep for `unchecked` across repo; invariant comment for each block
- [ ] `assembly` arithmetic reviewed separately
- [ ] Batch/mint/burn path mul+add edge case tests (max uint, 0, 1)
- [ ] Fee formulas: `mulDiv`, no division first
- [ ] Fuzz (Foundry) + invariant: `totalSupply == sum(balances)`
- [ ] Slither `integer-overflow` / `divide-before-multiply` warnings clean
- [ ] Upgradeable contracts: note storage packing with uint narrowing risk

---