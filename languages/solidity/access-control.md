# 🟠 Access Control Vulnerabilities

| Field | Value |
|-------|-------|
| **Severity** | 🔴 Critical → 🟠 High (depending on function impact) |
| **SWC** | [SWC-105](https://swcregistry.io/docs/SWC-105) Unprotected Ether Withdrawal · [SWC-106](https://swcregistry.io/docs/SWC-106) Unprotected SELFDESTRUCT · [SWC-115](https://swcregistry.io/docs/SWC-115) tx.origin |
| **CWE** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) Improper Access Control |
| **Related** | [tx-origin.md](tx-origin.md), [delegatecall-proxy.md](delegatecall-proxy.md), [reentrancy.md](reentrancy.md), case: [poly-network-2021](case-studies/poly-network-2021-610m-hack.md) |

---

## What Is It? (Explanation)

Access control answers the question **who can make which state change / fund movement**. Missing or incorrect protection:

- Anyone can call `withdraw`, `mint`, `setOwner`, `upgradeTo`, `selfdestruct`
- Wrong constructor naming (old Solidity) → init is public
- `initialize()` in proxy without `initializer` protection → attacker is first-caller owner
- `onlyOwner` forgotten on admin functions
- Auth via `tx.origin` → phishing contract ([tx-origin.md](tx-origin.md))
- Role confusion: `MINTER` and `DEFAULT_ADMIN` same wallet, or role admin chain is weak

On the blockchain, "unauthorized access" is not a web-style 403 — it is **irreversible asset transfer**.

---

## AI / Vibe Coding Patterns

| Prompt | AI's typical mistake |
|--------|----------------------|
| "Write a simple vault" | `withdrawAll` is public, no owner check |
| "Add Ownable" | Custom `owner` + `onlyOwner` halfway; `transferOwnership` missing/unsafe |
| "Upgradeable contract" | `initialize` is public, `initializer` modifier missing |
| "Admin pause/mint" | Modifier forgotten or only in comments |
| "Like multi-sig" | Single EOA owner; or anyone can `addOwner` |
| "tx.origin safer" | AI sometimes generates `tx.origin` which is vulnerable to phishing |

```
Prompt: "Owner should be able to withdraw funds, users should deposit"
AI:
function withdraw() public {  // 💀 no onlyOwner
    payable(owner).transfer(address(this).balance);
}
```

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

## Prevention Checklist

- [ ] Every state-changing function: who can call it? Make a table
- [ ] Do `public`/`external` admin functions have modifiers?
- [ ] Grep for `initialize` / `init` / `setup` → initializer protection
- [ ] Ownership: Ownable2Step or multi-sig; single EOA risk accepted in writing
- [ ] Role hierarchy: DEFAULT_ADMIN in separate cold wallet
- [ ] `delegatecall` / proxy admin in separate contract ([delegatecall-proxy.md](delegatecall-proxy.md))
- [ ] Slither `unprotected-upgrade`, `naming-convention` (constructor)
- [ ] Fork test: attacker EOA calling `withdraw`/`mint`/`upgrade` should revert
- [ ] Emergency pause in separate role; unpause more restrictive

---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Parity multi-sig #1** | 2017 | `initWallet`-like init was public → attacker becomes owner | Parity post-mortem / industry reports |
| **Parity library freeze** | 2017 | `killed` / ownership in library → `selfdestruct` → ~500k+ ETH locked | SWC-106 class, public post-mortems |
| **Rubixi** | ~2016 | Wrong constructor name → creator hijack | [SWC-105 Rubixi](https://swcregistry.io/docs/SWC-105) |
| **Poly Network** | 2021 | Cross-chain / keeper authority design → ~$610M (most returned) | [case-studies/poly-network-2021-610m-hack.md](case-studies/poly-network-2021-610m-hack.md) |
| **The DAO (2016)** | 2016 | Primary vector was reentrancy; org/governance trust model also broken | [dao-hack-2016-reentrancy.md](case-studies/dao-hack-2016-reentrancy.md), [reentrancy.md](reentrancy.md) |

---

## Vibe Coding Red Flags

```
🚩 onlyOwner in comment but not in code
🚩 function setOwner / setAdmin / mint / upgrade — no modifiers
🚩 initialize() public, no Initializable
🚩 owner = tx.origin or tx.origin == owner
🚩 Single private key admin + unlimited mint
🚩 AI custom Ownable (no event/zero-address/2-step)
🚩 selfdestruct or delegatecall public
🚩 Logic assumed "internal" is actually public
```

### AI prompt snippet

```
Use OpenZeppelin Ownable2Step and/or AccessControl.
Add the correct modifier to all admin/mint/pause/upgrade/withdraw functions.
Use msg.sender; tx.origin is forbidden.
If upgradeable, use Initializable + _disableInitializers() in constructor.
Least privilege: minter != admin. Events are mandatory.
```

---

**Severity: 🔴 Critical** — Unprotected withdraw/mint/upgrade = protocol takeover.
**SWC: SWC-105 / SWC-106** (+ SWC-115) · **Refs:** [SWC-105](https://swcregistry.io/docs/SWC-105), [SWC-106](https://swcregistry.io/docs/SWC-106), [OpenZeppelin Access](https://docs.openzeppelin.com/contracts/5.x/access-control)
