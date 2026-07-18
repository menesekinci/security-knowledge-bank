---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "Secure Fix (OpenZeppelin Proxy patterns)"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
---

## Secure Fix (OpenZeppelin Proxy patterns)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Implementation: upgradeable, storage append-only
contract SecureVaultV1 is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalAssets;
    /// @dev storage gap for future variables
    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // locks the implementation
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function setAssets(uint256 v) external onlyOwner {
        totalAssets = v;
    }
}

// V2: only APPEND storage after V1 layout; keep __gap shrink carefully
contract SecureVaultV2 is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalAssets;
    uint256 public feeBps; // new — was part of gap
    uint256[49] private __gap;

    constructor() { _disableInitializers(); }

    function initializeV2(uint256 _fee) external reinitializer(2) {
        feeBps = _fee;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// Deploy: ERC1967Proxy(implementation, abi.encodeCall(SecureVaultV1.initialize, (owner)))
```

**Rules (OZ):**

1. **Never** user-controlled `delegatecall` target.
2. Upgradeable: **OpenZeppelin Upgrades** plugin + `validateUpgrade`.
3. Storage: **append-only**; prefer `erc7201` namespaced storage (OZ 5).
4. Implementation constructor: **`_disableInitializers()`**.
5. Proxy admin / UUPS `_authorizeUpgrade` → multi-sig + timelock.
6. Transparent vs UUPS: know the selector clash and admin model.
7. For libraries: use trusted linked library or `call` + net state instead of `delegatecall`.
8. Check `delegatecall` success + returndata.
9. Reentrancy: external call via proxy still requires CEI ([reentrancy.md](reentrancy.md)).

---