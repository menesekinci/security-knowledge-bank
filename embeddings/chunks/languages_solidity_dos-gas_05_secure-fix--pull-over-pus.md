---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "Secure Fix (Pull over push, bounded batches)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
---

## Secure Fix (Pull over push, bounded batches)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureDistribute is ReentrancyGuard {
    mapping(address => uint256) public pending;

    function credit(address user, uint256 amount) internal {
        pending[user] += amount; // pull model
    }

    // User pulls themselves — no unbounded admin loop
    function withdraw() external nonReentrant {
        uint256 amount = pending[msg.sender];
        require(amount > 0, "zero");
        pending[msg.sender] = 0; // CEI — reentrancy.md
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }
}

contract SecureAuction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "low");
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid; // pull
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdrawRefund() external {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

// Bounded batch
contract BoundedSettle {
    uint256 public constant MAX_BATCH = 50;

    function settleBatch(uint256[] calldata ids) external {
        require(ids.length <= MAX_BATCH, "batch");
        for (uint256 i = 0; i < ids.length; i++) {
            _settle(ids[i]);
        }
    }

    function _settle(uint256 id) internal { /* ... */ }
}
```

**Rules:**

1. **Pull over push** — reward/refund is pulled by the user.
2. **Hard upper bound** on batches (`MAX_BATCH`).
3. If there's an external call in a loop: one failure should not lock the entire system (isolation or pull).
4. Don't bind to a foreign `receive` with `require(ok)` on DoS-critical paths.
5. Pagination / cursor with state machine (`nextIndex`).
6. Growing structures like ERC721A / enumerable: off-chain index + on-chain claim.
7. Reentrancy: CEI + `nonReentrant` ([reentrancy.md](reentrancy.md)).

---