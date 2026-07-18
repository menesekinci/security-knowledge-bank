# 🟠 Integer Overflow / Underflow

| Field | Value |
|-------|-------|
| **Severity** | 🟠 High (drops with 0.8+ default check; critical again with `unchecked`) |
| **SWC** | [SWC-101](https://swcregistry.io/docs/SWC-101) — Integer Overflow and Underflow |
| **CWE** | [CWE-190](https://cwe.mitre.org/data/definitions/190.html) / [CWE-191](https://cwe.mitre.org/data/definitions/191.html) / [CWE-682](https://cwe.mitre.org/data/definitions/682.html) |
| **Related** | [reentrancy.md](reentrancy.md), [flash-loan.md](flash-loan.md), [unchecked-calls.md](unchecked-calls.md) |

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

## Vulnerable Code (Solidity)

### 1) Pre-0.8 silent wrap (classic)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableToken {
    mapping(address => uint256) public balances;

    // 💀 cnt * value overflow → amount comes out small, require passes
    function batchTransfer(address[] memory receivers, uint256 value) public {
        uint256 cnt = receivers.length;
        uint256 amount = cnt * value; // wrap possible
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < cnt; i++) {
            balances[receivers[i]] += value;
        }
    }
}
```

### 2) 0.8+ but same bug with `unchecked`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableUnchecked {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        // 💀 underflow wrap when balance insufficient → huge balance
        unchecked {
            balances[msg.sender] -= amount;
        }
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
```

### 3) Logical / precision (checked math not enough)

```solidity
// 💀 (amount * feeBps) / 10000 — if amount is large, intermediate overflow reverts
// or vice versa: divide first → fee = 0 (free trade)
function fee(uint256 amount, uint256 feeBps) pure returns (uint256) {
    return (amount / 10000) * feeBps; // precision loss
}
```

---

## Secure Fix (OpenZeppelin / 0.8 patterns)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract SecureToken {
    using SafeCast for uint256;
    mapping(address => uint256) public balances;

    function batchTransfer(address[] calldata receivers, uint256 value) external {
        uint256 cnt = receivers.length;
        require(cnt > 0 && cnt <= 100, "bad len");
        // 0.8 checked mul — overflow → revert
        uint256 amount = cnt * value;
        require(balances[msg.sender] >= amount, "bal");
        balances[msg.sender] -= amount; // checked sub
        for (uint256 i = 0; i < cnt; i++) {
            balances[receivers[i]] += value;
        }
    }

    // Intentional unchecked: only in proven non-overflow regions
    function sumKnownSafe(uint256 a, uint256 b) pure returns (uint256) {
        // e.g., if a < 2^128, b < 2^128 proven:
        unchecked {
            return a + b;
        }
    }

    // mulDiv: overflow-safe intermediate computation (OZ Math)
    function quote(uint256 amount, uint256 price, uint256 scale)
        pure
        returns (uint256)
    {
        return Math.mulDiv(amount, price, scale);
    }
}
```

**Rules:**

1. Use `pragma solidity ^0.8.x`; don't open `unchecked` unnecessarily.
2. For pre-0.8 legacy: use OpenZeppelin **SafeMath** (or upgrade).
3. `unchecked` only for: loop index `++`, or mathematically proven bounds + comments.
4. Use `Math.mulDiv` / `mulDivRoundingUp` for fee/price calculations.
5. Use `SafeCast.toUint96` etc. for downcasting.

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

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **BeautyChain (BEC)** | 2018 | `cnt * value` overflow in `batchTransfer` → massive mint/transfer | [SWC-101 BEC sample](https://swcregistry.io/docs/SWC-101), media post-mortems |
| **SmartMesh (SMT) / similar token bugs** | 2018 | Supply corruption via ERC20 arithmetic overflow | Industry write-ups (SWC-101 class) |
| **Capture the Ether — Token Sale** | educational | `numTokens * PRICE` overflow for cheap purchase | [SWC-101](https://swcregistry.io/docs/SWC-101) |

Note: After Solidity 0.8, "classic" wrapping has decreased; modern risk is the **`unchecked` + wrong formula + assembly** triad. Amounts amplified by flash loans can trigger overflow/precision edges → [flash-loan.md](flash-loan.md).

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
