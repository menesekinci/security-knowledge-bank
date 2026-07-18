# 🟡 Delegatecall & Proxy Storage Risks

| Field | Value |
|-------|-------|
| **Severity** | 🔴 Critical (storage corruption / full takeover) |
| **SWC** | [SWC-112](https://swcregistry.io/docs/SWC-112) — Delegatecall to Untrusted Callee |
| **CWE** | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Inclusion of Functionality from Untrusted Control Sphere |
| **Related** | [access-control.md](access-control.md), [reentrancy.md](reentrancy.md), [unchecked-calls.md](unchecked-calls.md), case: [wormhole-bridge-2022](case-studies/wormhole-bridge-2022-signature-bypass.md) |

---

## What Is It?

`delegatecall` executes the target contract's **code** in the calling contract's **storage / msg.sender / msg.value** context.

```
proxy.storage  +  implementation.code  =  executed logic
```

This is the foundation of **upgradeable proxy** (Transparent, UUPS, Beacon) and library patterns. Risks:

1. **Untrusted delegatecall target** — attacker implementation → can write any storage slot (`owner`, balances).
2. **Storage layout collision** — if proxy and implementation (or V1→V2) slot order shifts, variables overwrite each other.
3. **Uninitialized implementation / proxy** — `initialize` is public; attacker becomes owner ([access-control.md](access-control.md)).
4. **Function selector clashing** — admin and implementation share the same selector (Transparent proxy separates them).
5. **UUPS `upgradeTo` unauthorized / missing `_authorizeUpgrade`**.
6. **`selfdestruct` in implementation** (legacy): killing proxy code via delegatecall (Parity-class); Cancun restricted `SELFDESTRUCT` but **storage wipe / legacy** is still an audit concern.
7. **`delegatecall` return unchecked** → [unchecked-calls.md](unchecked-calls.md).

The DAO (2016) was reentrancy; the iconic event for the proxy/delegatecall class is **Parity Wallet (2017)** and modern **bridge/proxy init** bugs.

---

## AI / Vibe Coding Patterns

| Prompt | AI Mistake |
|--------|------------|
| "Write an upgradeable ERC20" | No storage gap; V2 new variable at slot 0 |
| "Use proxy" | `delegatecall` to `msg.sender` or user input address |
| "Initialize owner" | No `initialized` in implementation; attacker inits |
| "Simple proxy" | Fallback delegatecall, no admin separation |
| "Copy OZ" | Old OZ, missing `_disableInitializers` |

```
Prompt: "Execute logic with the library address provided by user"
AI:
function execute(address lib, bytes calldata data) external {
  lib.delegatecall(data); // 💀 SWC-112
}
```

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

## Prevention Checklist

- [ ] `delegatecall` grep — target constant / whitelist / OZ proxy only?
- [ ] Implementation `initialize` + `_disableInitializers`
- [ ] Storage layout: `forge inspect` / OZ storage check V1 vs V2
- [ ] `__gap` or namespaced storage
- [ ] Upgrade path: onlyOwner/AccessControl + timelock
- [ ] Implementation contract self-call attack test (init)
- [ ] No `selfdestruct` in logic used via delegatecall
- [ ] Slither `controlled-delegatecall`, `unprotected-upgrade`
- [ ] Wormhole-class: don't confuse guardian/sig verification with proxy admin — separate threat model

---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Parity multi-sig / library** | 2017 | Library ownership + `delegatecall` pattern → wallet freeze / drain class events | Public post-mortems, SWC-112 context |
| **Uninitialized proxy/implementation wave** | 2020– | Initialize front-run on various protocols | Audit findings (OpenZeppelin guidance) |
| **Audius governance** | 2022 | Proxy/governance storage & upgrade related critical issue (community post-mortem) | Public Audius incident reports |
| **Wormhole** | 2022 | Primary vector signature/sysaccount — lesson on bridge/proxy trust surface | [wormhole-bridge-2022-signature-bypass.md](case-studies/wormhole-bridge-2022-signature-bypass.md) |

Refs: [SWC-112](https://swcregistry.io/docs/SWC-112), [OpenZeppelin Proxy docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies), [UUPS](https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable).

---

## Vibe Coding Red Flags

```
🚩 delegatecall(userAddress, ...)
🚩 No storage gap in upgradeable contract
🚩 Variable order changed in V2
🚩 initialize public, no _disableInitializers
🚩 upgradeTo open to everyone
🚩 AI custom proxy (no OZ)
🚩 Blindly delegatecall'ing msg.data
🚩 Assuming constructor state + proxy state are mixed
🚩 Comment saying "delegatecall = call"
```

### AI prompt snippet

```
For upgradeable: use OpenZeppelin UUPS/Transparent + Upgrades plugin.
No delegatecall to user input.
_disableInitializers() in implementation constructor.
Storage only appended at the end; gap or EIP-7201 namespace.
_authorizeUpgrade onlyOwner/multi-sig. Run validateUpgrade.
```

---

**Severity: 🔴 Critical** — A single bad `delegatecall` or storage collision = full storage write / protocol takeover.
**SWC: SWC-112** · **Refs:** [SWC-112](https://swcregistry.io/docs/SWC-112), [OZ Proxies](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies), [SWC Registry](https://swcregistry.io/)
