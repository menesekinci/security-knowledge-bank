---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
---

## Vulnerable Code (Solidity)

### 1) Delegatecall to user-controlled address

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableProxy {
    address public owner;

    // 💀 attacker lib: owner = attacker slot write
    function forward(address lib, bytes calldata data) external {
        (bool ok, ) = lib.delegatecall(data);
        require(ok);
    }
}

// AttackerLib:
// function pwn() external { assembly { sstore(0, caller()) } }
```

### 2) Storage collision (simplified)

```solidity
// Proxy / V1
contract V1 {
    address public implementation; // slot 0
    address public owner;          // slot 1
    uint256 public value;          // slot 2
}

// 💀 V2 developer "moved owner to top"
contract V2_Bad {
    address public owner;          // slot 0 — overwrites implementation address!
    address public implementation; // slot 1
    uint256 public value;
    uint256 public newVar;
}
```

### 3) Uninitialized implementation

```solidity
contract VulnerableImpl {
    address public owner;
    bool private inited;

    function initialize() external {
        // 💀 if logic contract is called directly, attacker becomes owner
        require(!inited);
        inited = true;
        owner = msg.sender;
    }

    function sensitive() external {
        require(msg.sender == owner);
        // ...
    }
}
```

### 4) Missing upgrade auth (UUPS-style sketch)

```solidity
contract VulnerableUUPS {
    address public implementation;

    // 💀 anyone can upgrade
    function upgradeTo(address newImpl) external {
        implementation = newImpl;
    }
}
```

---