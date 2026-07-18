---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "What Is It? (Explanation)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
---

## What Is It? (Explanation)

In Solidity, integer types are fixed-size (`uint8` → 0…255, `uint256` → 0…2²⁵⁶−1). If the arithmetic result goes outside this range:

- **Overflow:** `max + 1` → `0` (or wrap)
- **Underflow:** `0 - 1` → `type(uint).max`

**Solidity < 0.8.0:** `+`, `-`, `*` silently wraps (EVM opcode behavior). SafeMath library was mandatory.

**Solidity ≥ 0.8.0:** Default arithmetic **reverts** on overflow/underflow. However:

1. `unchecked { ... }` block disables protection (commonly used for gas savings).
2. Assembly (`assembly { ... }`) has no checked math.
3. Type conversions (`uint256` → `uint8`) and `abi.encodePacked` truncations are separate risks.
4. Logical overflow (wrong formula: `amount * price / scale` order) can produce **wrong results** even with checked math; it won't revert.

---