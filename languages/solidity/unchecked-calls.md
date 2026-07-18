# 🟡 Unchecked External Calls

| Field | Value |
|------|--------|
| **Severity** | 🟡 Medium → 🟠 High (silent loss of funds / state drift) |
| **SWC** | [SWC-104](https://swcregistry.io/docs/SWC-104) — Unchecked Call Return Value |
| **CWE** | [CWE-252](https://cwe.mitre.org/data/definitions/252.html) Unchecked Return Value |
| **Related** | [reentrancy.md](reentrancy.md), [dos-gas.md](dos-gas.md), [access-control.md](access-control.md) |

---

### What Is It? (Explanation)

Low-level calls in Solidity:

- `address.call(...)`
- `address.delegatecall(...)`
- `address.staticcall(...)`
- Legacy: `send`, some uses of `call`

return a **boolean success**. If this value is **not checked**, the contract keeps running even when the call fails: the balance is assumed deducted, an event is emitted, and the accounting is corrupted.

In addition, ERC20 `transfer` / `transferFrom` on some tokens (such as `USDT`) **do not return a bool** or always return false — which is why a raw `token.transfer` + `require` is also fragile; **SafeERC20** should be used.

If `transfer()` (2300 gas) fails it **reverts** (an exception, not a return check). But `send()` returns false and **does not revert** — the classic unchecked pattern.

An external call also opens up a **reentrancy** surface → [reentrancy.md](reentrancy.md). A failing recipient can be a **DoS** tool → [dos-gas.md](dos-gas.md).

---

## AI / Vibe Coding Patterns

| Prompt | AI mistake |
|--------|-----------|
| "Send ETH" | `addr.send(amount);` return ignored |
| "Send flexibly with call" | `(bool ok,) = call;` `ok` unused |
| "ERC20 withdraw" | `IERC20.transfer` incompatible with USDT |
| "Low-level optimize" | success ignored + state update |
| "Forgot try/catch" | External contract call exception swallowed |

```
Prompt: "Pay the user"
AI:
balances[msg.sender] = 0;
msg.sender.send(amount); // 💀 balance is 0 even if it fails
```

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

## Secure Fix (OZ SafeERC20 + checked call)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract SecurePayout is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Address for address payable;

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "zero");
        balances[msg.sender] = 0; // CEI
        // Address.sendValue: call + require success
        payable(msg.sender).sendValue(amount);
        // or:
        // (bool ok, ) = msg.sender.call{value: amount}("");
        // require(ok, "ETH xfer");
    }

    function withdrawToken(IERC20 token, address to, uint256 amount) external nonReentrant {
        // fee-on-transfer may require a separate balance-before/after design
        token.safeTransfer(to, amount);
    }
}

// external contract via try/catch (when the return data matters)
contract SecureExternal {
    function callOther(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call fail");
        return ret;
    }
}
```

**Rules:**

1. Every `call` / `send` / `delegatecall`: **check success**, or a deliberate "best-effort" + documentation (rarely).
2. ETH: `Address.sendValue` or `call` + `require`.
3. ERC20: **SafeERC20** (`safeTransfer`, `safeTransferFrom`, `forceApprove`).
4. **CEI** + **nonReentrant** — a success check does not solve reentrancy.
5. `transfer()` (2300 gas) can fall short with modern recipient contracts; prefer `call` + check.
6. Batch: a success policy per sub-call (all-or-nothing vs. continue + event).
7. Return data: check `ok` before `abi.decode`.

---

## Prevention Checklist

- [ ] grep `\.send\(` and `\.call\{` — every one has `require(ok)` or an OZ helper
- [ ] ERC20 outflows use SafeERC20
- [ ] Fee-on-transfer / rebasing token assumptions are covered in tests
- [ ] CEI ordering: state → interaction
- [ ] ReentrancyGuard on sensitive withdraw paths
- [ ] Fail path: are the event + accounting consistent (no double payment / loss)?
- [ ] If try/catch is used, ban empty catch blocks
- [ ] Slither `unchecked-transfer`, `low-level-calls`

---

## Real Incidents

| Incident | Year | Summary | Source |
|------|-----|------|--------|
| **King of the Ether / early games** | ~2016 | `send` fail / gas stipend breaking crown/payout logic | Historical analyses, SWC-104 class |
| **SWC-104 canonical samples** | — | `callee.call()` unchecked | [SWC-104](https://swcregistry.io/docs/SWC-104) |
| **USDT-class ERC20 quirks** | continuous | Non-standard return → integration failure or false trust | OpenZeppelin SafeERC20 rationale |
| **Batch bridges / multisend bugs** | various audits | Partial call fail ignored → accounting desync | Public audit reports (pattern class) |

The DAO Hack is primarily tied to reentrancy + call usage; the **CEI violation** stands out more than the return value — but the low-level `call` surface is common to both: [reentrancy.md](reentrancy.md), [dao-hack-2016](case-studies/dao-hack-2016-reentrancy.md).

---

## Vibe Coding Red Flags

```
🚩 .send( without if/require
🚩 (bool ok,) = ...call; and ok is never used
🚩 token.transfer / transferFrom with no SafeERC20
🚩 balances=0 then unchecked send
🚩 AI: "call always returns true"
🚩 empty catch {} on external call
🚩 success ignored + "paid" event
🚩 assuming a modern recipient contract with a 2300 gas transfer
```

### AI prompt snippet

```
Check every low-level call/send result with require.
For ETH use Address.sendValue or call+require.
For ERC20 use OpenZeppelin SafeERC20.
Checks-Effects-Interactions + ReentrancyGuard.
Do not update state as a "successful payment" when it fails.
```

---

**Severity: 🟡–🟠** — Silent payment failure → user loss of funds or accounting exploit.
**SWC: SWC-104** · **Refs:** [SWC-104](https://swcregistry.io/docs/SWC-104), [ConsenSys — external calls](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/), [OpenZeppelin SafeERC20](https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#SafeERC20), [Address.sendValue](https://docs.openzeppelin.com/contracts/5.x/api/utils#Address)
