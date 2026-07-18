# 🟡 Denial of Service via Gas (DoS)

| Field | Value |
|-------|-------|
| **Severity** | 🟡 Medium → 🟠 High (fund lock / governance paralysis) |
| **SWC** | [SWC-128](https://swcregistry.io/docs/SWC-128) — DoS With Block Gas Limit |
| **CWE** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption |
| **Related** | [unchecked-calls.md](unchecked-calls.md), [reentrancy.md](reentrancy.md), [front-running.md](front-running.md) |

---

## What Is It? (Explanation)

On Ethereum, every block and every TX has a **gas limit**. Contract logic that:

1. Has an **unbounded / attacker-enlarged loop** (paying everyone from an array),
2. Sends to an **external call** that consumes gas or always reverts,
3. Has a "process all users" batch that hits the **block gas limit**,

becomes **DoSed** if it cannot be executed: nobody can claim, auction cannot progress, governance cannot execute, funds get locked.

Classic sub-types:

| Type | Mechanism |
|------|-----------|
| **Unbounded mass pull** | `for (i < users.length)` `transfer` to everyone — list grows |
| **Push payment griefing** | Receiver `receive()` revert → entire function reverts |
| **Block gas limit** | Too much work in a single TX |
| **Gas griefing (external)** | Leaving too little gas for subcall / 63/64 rule |
| **Storage spam** | Writing garbage to mapping to increase operational cost |

Relationship: push payment + revert intersects with [unchecked-calls.md](unchecked-calls.md); should not be confused with reentrancy guard vs DoS.

---

## AI / Vibe Coding Patterns

| Prompt | AI error |
|--------|----------|
| "Distribute rewards to everyone" | `for` + `transfer` unbounded |
| "Auction refund previous" | Push refund inside `bid()`; reverting bidder DoS |
| "Delete all stakers" | Entire array in one TX |
| "Airdrop N address" | N is user-controlled, gas DoS |
| `require(success)` on every send | One bad receiver kills entire batch |

```
Prompt: "Share profits to investors"
AI:
function distribute() external {
  for (uint i; i < investors.length; i++) {
    payable(investors[i]).transfer(share); // 💀
  }
}
```

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

## Secure Fix (Pull over push, bounded batches)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureDistribute is ReentrancyGuard {
    mapping(address => uint256) public pending;

    function credit(address user, uint256 amount) internal {
        pending[user] += amount; // pull model
    }

    // User pulls themselves — no unbounded admin loop
    function withdraw() external nonReentrant {
        uint256 amount = pending[msg.sender];
        require(amount > 0, "zero");
        pending[msg.sender] = 0; // CEI — reentrancy.md
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }
}

contract SecureAuction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "low");
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid; // pull
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdrawRefund() external {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

// Bounded batch
contract BoundedSettle {
    uint256 public constant MAX_BATCH = 50;

    function settleBatch(uint256[] calldata ids) external {
        require(ids.length <= MAX_BATCH, "batch");
        for (uint256 i = 0; i < ids.length; i++) {
            _settle(ids[i]);
        }
    }

    function _settle(uint256 id) internal { /* ... */ }
}
```

**Rules:**

1. **Pull over push** — reward/refund is pulled by the user.
2. **Hard upper bound** on batches (`MAX_BATCH`).
3. If there's an external call in a loop: one failure should not lock the entire system (isolation or pull).
4. Don't bind to a foreign `receive` with `require(ok)` on DoS-critical paths.
5. Pagination / cursor with state machine (`nextIndex`).
6. Growing structures like ERC721A / enumerable: off-chain index + on-chain claim.
7. Reentrancy: CEI + `nonReentrant` ([reentrancy.md](reentrancy.md)).

---

## Prevention Checklist

- [ ] `for` + `recipients.length` / `users.length` grep — is there a bound?
- [ ] Payment: is it pull model?
- [ ] Auction/refund: no push
- [ ] Max length on batch functions
- [ ] Worst-case gas estimate (full array, hostile receiver)
- [ ] Griefing test: reverting receiver contract
- [ ] Governance execute: large operations timelock + split
- [ ] Slither `arbitrary-send-eth`, loops heuristics

---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **GovernMental** | ~2016 | Pyramid/ponzi-style contract; large state + gas → stuck | Classic Ethereum DoS case studies / SWC-128 discussions |
| **King of the Ether Throne** | early ETH | Claim/crown transition and gas/call edge cases | Historical contract analyses |
| **Various ICO refund loops** | 2017–18 | Push refund on investor list → gas limit | Industry audits (class pattern) |
| **Auction griefing (generic)** | continuous | Reverting bidder / smart contract wallet edge | SWC-128, ConsenSys best practices |

Refs: [SWC-128](https://swcregistry.io/docs/SWC-128), [ConsenSys — DoS](https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/).

---

## Vibe Coding Red Flags

```
🚩 for (i < array.length) { payable(x).transfer }
🚩 distribute / payoutAll / refundAll single TX
🚩 previous.transfer inside bid()
🚩 "require(success)" to foreign address inside batch
🚩 No MAX_BATCH; AI processes "all at once"
🚩 Deletion: while(array.length>0) pop + external
🚩 Assumption that gas limit is "high enough"
```

### AI Prompt Snippet

```
Use pull-over-push for payments; mapping pending + withdraw.
Never make external calls inside an unbounded loop.
Use MAX_BATCH limit and cursor for batch operations.
Reverting receiver should not lock the entire protocol.
Checks-Effects-Interactions + ReentrancyGuard.
```

---

**Severity: 🟡–🟠** — Funds can be locked without being stolen; governance/auction paralysis.
**SWC: SWC-128** · **Refs:** [SWC Registry SWC-128](https://swcregistry.io/docs/SWC-128), OpenZeppelin payment/pull patterns in docs & examples
