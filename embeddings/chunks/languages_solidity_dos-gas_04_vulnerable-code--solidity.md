---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
---

## Vulnerable Code (Solidity)

### 1) Unbounded loop + push

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableDistribute {
    address[] public recipients;
    mapping(address => uint256) public shares;

    function addRecipient(address r, uint256 share) external {
        recipients.push(r);
        shares[r] = share;
    }

    // 💀 As recipients grows, block gas limit → distribute becomes impossible
    // 💀 If one recipient reverts (contract has no receive), entire distribution fails
    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            address r = recipients[i];
            uint256 amount = shares[r];
            (bool ok, ) = r.call{value: amount}("");
            require(ok, "fail"); // griefing
        }
    }
}
```

### 2) Auction push refund DoS

```solidity
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid);
        // 💀 If previous bidder is a reverting contract, bid() always fails
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

### 3) Progress depends on full array clear

```solidity
// 💀 never completable if array huge
function settleAll(uint256[] calldata ids) external {
    for (uint256 i = 0; i < ids.length; i++) {
        _settle(ids[i]); // heavy storage
    }
}
```

---