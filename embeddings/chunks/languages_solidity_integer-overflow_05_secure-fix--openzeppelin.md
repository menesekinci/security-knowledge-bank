---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "Secure Fix (OpenZeppelin / 0.8 patterns)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
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