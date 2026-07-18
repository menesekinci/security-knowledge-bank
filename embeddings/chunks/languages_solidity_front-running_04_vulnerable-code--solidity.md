---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
---

## Vulnerable Code (Solidity)

### 1) Swap without slippage protection

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract VulnerableAMM {
    // simplified x*y=k
    uint256 public reserveA;
    uint256 public reserveB;

    // 💀 No minAmountOut / deadline — sandwich
    function swapAforB(uint256 amountA) external {
        uint256 amountB = (amountA * reserveB) / (reserveA + amountA);
        IERC20(tokenA).transferFrom(msg.sender, address(this), amountA);
        reserveA += amountA;
        reserveB -= amountB;
        IERC20(tokenB).transfer(msg.sender, amountB);
    }

    address tokenA;
    address tokenB;
}
```

### 2) Last-second front-run on auction

```solidity
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;

    // 💀 Bid visible in mempool; bot jumps ahead with +1 wei
    function bid() external payable {
        require(msg.value > highestBid);
        // refund push to old bidder — also DoS risk (dos-gas.md)
        payable(highestBidder).transfer(highestBid);
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

### 3) ERC20 approve race (classic order dependence)

```solidity
// 💀 approve(spender, newAmount): spender sees it in mempool, spends with old allowance,
// then also uses the new approve (double-spend allowance)
function approve(address spender, uint256 amount) public returns (bool) {
    allowance[msg.sender][spender] = amount;
    return true;
}
```

---