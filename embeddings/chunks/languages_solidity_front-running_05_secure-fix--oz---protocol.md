---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "Secure Fix (OZ + protocol patterns)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
---

## Secure Fix (OZ + protocol patterns)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SaferSwap {
    uint256 public reserveA;
    uint256 public reserveB;

    function swapAforB(
        uint256 amountA,
        uint256 minAmountOut,   // slippage
        uint256 deadline
    ) external returns (uint256 amountB) {
        require(block.timestamp <= deadline, "expired");
        amountB = (amountA * reserveB) / (reserveA + amountA);
        require(amountB >= minAmountOut, "slippage");
        // transfers + update reserves...
    }
}

// Commit-reveal (e.g., sealed bid / fair mint)
contract CommitReveal {
    mapping(address => bytes32) public commits;
    mapping(address => bool) public revealed;

    function commit(bytes32 h) external {
        commits[msg.sender] = h; // h = keccak256(abi.encodePacked(value, salt, msg.sender))
    }

    function reveal(uint256 value, bytes32 salt) external {
        require(commits[msg.sender] == keccak256(abi.encodePacked(value, salt, msg.sender)));
        require(!revealed[msg.sender]);
        revealed[msg.sender] = true;
        // settle with value
    }
}

// Approve: increase/decrease or permit (EIP-2612)
// OpenZeppelin ERC20: increaseAllowance / decreaseAllowance / permit
```

**MEV-resistant design options:**

1. **Slippage + deadline** on every swap/liquidity op.
2. **Commit-reveal** or **encrypted mempool** / threshold encrypt (protocol-dependent).
3. **Batch auctions** (CowSwap style) — reduces order sensitivity.
4. **Private orderflow** (builder/relay) — user side; contract still requires minOut.
5. **TWAP / limit orders** via off-chain keeper.
6. Liquidation: partial liq, Dutch auction, or keeper network + fair gas.
7. `approve` → `increaseAllowance` / `permit` / set to 0 then new amount.
8. Flash loan + MEV combination for oracle and pool isolation → [flash-loan.md](flash-loan.md), [oracle-manipulation.md](oracle-manipulation.md).

---