---
source: "languages/solidity/integer-overflow.md"
title: "🟠 Integer Overflow / Underflow"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
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