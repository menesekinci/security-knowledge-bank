---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 3/7
---

## Vulnerable Code (Solidity)

### 1) send() unchecked

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerablePayout {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 💀 send can return false (gas / recipient revert); balance is still cleared
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.send(amount); // return ignored
    }
}
```

### 2) call without check

```solidity
contract VulnerableCall {
    // 💀 SWC-104 sample pattern
    function pay(address payable to, uint256 amount) external {
        to.call{value: amount}(""); // success ignored
        // accounting: assumes "paid"
    }
}
```

### 3) ERC20 raw transfer

```solidity
interface IERC20Raw {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerableERC20Out {
    IERC20Raw public token;

    function unsafeWithdraw(address to, uint256 amount) external {
        // 💀 some tokens don't return a bool → ABI decode revert
        // 💀 some return false, no require → silent fail
        token.transfer(to, amount);
    }
}
```

### 4) Swallowing a partial fail in a multi-call

```solidity
function batch(address[] calldata targets, bytes[] calldata data) external {
    for (uint i; i < targets.length; i++) {
        targets[i].call(data[i]); // 💀 which one failed?
    }
}
```

---