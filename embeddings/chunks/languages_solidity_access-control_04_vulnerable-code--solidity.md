---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
---

## Vulnerable Code (Solidity)

### 1) Missing onlyOwner

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    constructor() { owner = msg.sender; }

    function deposit() external payable {}

    // 💀 SWC-105 — anyone can withdraw all ETH
    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    // 💀 owner hijack
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
```

### 2) Unprotected initialize (proxy)

```solidity
contract VulnerableInit {
    address public owner;
    bool private initialized;

    // 💀 anyone can become owner once (or repeatedly if no flag)
    function initialize(address _owner) external {
        // initialized check missing or race condition
        owner = _owner;
        initialized = true;
    }
}
```

### 3) Unprotected selfdestruct (SWC-106)

```solidity
// 💀 anyone can kill the contract and take the balance (legacy pattern)
function kill() public {
    selfdestruct(payable(msg.sender));
}
```

### 4) Wrong constructor name (legacy)

```solidity
// Solidity 0.4.x — if the name doesn't match, anyone can call the "constructor" at runtime
contract RubixiStyle {
    address private creator;
    function DynamicPyramid() public { // 💀 not a constructor
        creator = msg.sender;
    }
}
```

---