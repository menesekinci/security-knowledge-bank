---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "Secure Fix (OpenZeppelin patterns)"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
---

## Secure Fix (OpenZeppelin patterns)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// --- Simple vault: Ownable2Step preferred ---
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract SecureVault is Ownable2Step, Pausable, ReentrancyGuard {
    constructor(address initialOwner) Ownable(initialOwner) {}

    function deposit() external payable whenNotPaused {}

    function withdraw(uint256 amount) external onlyOwner nonReentrant {
        (bool ok, ) = payable(owner()).call{value: amount}("");
        require(ok, "xfer");
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}

// --- Roles: separating mint vs admin ---
contract SecureToken is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        // admin != minter recommended (least privilege)
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        // _mint(to, amount);
    }
}

// --- Proxy init ---
contract SecureUpgradeable is Initializable {
    address public owner;

    function initialize(address _owner) external initializer {
        require(_owner != address(0), "zero");
        owner = _owner;
    }
}
```

**Best practices:**

1. OpenZeppelin **Ownable2Step** (reduces risk of transferring ownership to wrong address).
2. **AccessControl** / **AccessControlEnumerable** — roles, `grantRole` only by admin.
3. Upgradeable: `Initializable` + `initializer` / `reinitializer`; `_disableInitializers()` in constructor.
4. `msg.sender`, never `tx.origin` for auth ([tx-origin.md](tx-origin.md)).
5. Do not use `selfdestruct` (ETH destruction behavior changed after Cancun; still admin-only and generally avoid).
6. Timelock + multi-sig (Gnosis Safe) for production admin.
7. Critical ops: event log + two-step + delay.

---