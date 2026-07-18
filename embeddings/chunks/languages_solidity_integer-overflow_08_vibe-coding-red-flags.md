---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 pragma solidity ^0.4 / ^0.5 / ^0.6 / ^0.7 and no SafeMath
🚩 unchecked everywhere for "gas save"
🚩 amount * price / 1e18 order not considered
🚩 uint8/uint16 balance or fee fields (easy wrap)
🚩 AI: "overflow is impossible in 0.8" — wrong (unchecked/assembly)
🚩 Loop: balances[i] += x no invariant test
🚩 Batch length * value before require
```

### AI Prompt Snippet

```
Use Solidity ^0.8.20. Keep arithmetic checked by default.
Use unchecked only in proven safe places with comments.
Use OpenZeppelin Math.mulDiv for multiplication/division.
Batch transfer: check length*value overflow and max batch limit.
Preserve totalSupply invariant. Ban assembly arithmetic (unless necessary).
```

---

**Severity: 🟠 High** — Pre-0.8 or with `unchecked`, token supply / balance corruption; formula errors in checked 0.8 still cause fund loss.
**SWC: SWC-101** · **Refs:** [SWC Registry](https://swcregistry.io/docs/SWC-101), [ConsenSys — Insecure Arithmetic](https://consensys.github.io/smart-contract-best-practices/attacks/insecure-arithmetic/), [OpenZeppelin Math](https://docs.openzeppelin.com/contracts/5.x/api/utils#Math)