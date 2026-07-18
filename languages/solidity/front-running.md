# 🟠 Front-Running & MEV

| Field | Value |
|-------|-------|
| **Severity** | 🟠 High (value extraction / unfair ordering) |
| **SWC** | [SWC-114](https://swcregistry.io/docs/SWC-114) — Transaction Order Dependence |
| **CWE** | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource |
| **Related** | [flash-loan.md](flash-loan.md), [oracle-manipulation.md](oracle-manipulation.md), [reentrancy.md](reentrancy.md) |

---

## What Is It? (Explanation)

Transactions waiting in the mempool on Ethereum (and most L1/L2s) are **visible to everyone**. Block producers / search bots can select the order of transactions or insert their own.

**Front-running:** Seeing a user TX and placing **your own TX before it**.  
**Back-running:** Placing right **after** a user TX.  
**Sandwich:** Before + after → squeezing the user via slippage on AMM.  
**MEV (Maximal Extractable Value):** Value extracted through ordering, insertion, censorship (tip, sandwich, liquidation race, arbitrage).

SWC-114 **transaction order dependence**: if contract logic is sensitive to the order of TXs in the same block, an attacker can turn the order to their advantage.

This is as much a **design constraint** as a "bug": blockchain is atomic and ordered; naive "first come wins" and "visible price quote" models are exposed to MEV.

---

## AI / Vibe Coding Patterns

| Prompt | AI error |
|--------|----------|
| "Write a DEX swap" | No slippage / deadline → sandwich |
| "NFT mint, first-come" | No commit-reveal; bot mint |
| "Liquidation function" | Public race; MEV liquidation |
| "Buy at oracle price" | Oracle update + trade visible in mempool |
| "Sealed bid auction" | Single TX bid on-chain and visible |

```
Prompt: "Uniswap-like swap"
AI:
function swap(address tokenIn, address tokenOut, uint amountIn) external {
    uint out = getAmountOut(amountIn); // 💀 no minOut
    // transfer...
}
```

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

## Secure Fix (OZ + protocol patterns)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SaferSwap {
    uint256 public reserveA;
    uint256 public reserveB;

    function swapAforB(
        uint256 amountA,
        uint256 minAmountOut,   // slippage
        uint256 deadline
    ) external returns (uint256 amountB) {
        require(block.timestamp <= deadline, "expired");
        amountB = (amountA * reserveB) / (reserveA + amountA);
        require(amountB >= minAmountOut, "slippage");
        // transfers + update reserves...
    }
}

// Commit-reveal (e.g., sealed bid / fair mint)
contract CommitReveal {
    mapping(address => bytes32) public commits;
    mapping(address => bool) public revealed;

    function commit(bytes32 h) external {
        commits[msg.sender] = h; // h = keccak256(abi.encodePacked(value, salt, msg.sender))
    }

    function reveal(uint256 value, bytes32 salt) external {
        require(commits[msg.sender] == keccak256(abi.encodePacked(value, salt, msg.sender)));
        require(!revealed[msg.sender]);
        revealed[msg.sender] = true;
        // settle with value
    }
}

// Approve: increase/decrease or permit (EIP-2612)
// OpenZeppelin ERC20: increaseAllowance / decreaseAllowance / permit
```

**MEV-resistant design options:**

1. **Slippage + deadline** on every swap/liquidity op.
2. **Commit-reveal** or **encrypted mempool** / threshold encrypt (protocol-dependent).
3. **Batch auctions** (CowSwap style) — reduces order sensitivity.
4. **Private orderflow** (builder/relay) — user side; contract still requires minOut.
5. **TWAP / limit orders** via off-chain keeper.
6. Liquidation: partial liq, Dutch auction, or keeper network + fair gas.
7. `approve` → `increaseAllowance` / `permit` / set to 0 then new amount.
8. Flash loan + MEV combination for oracle and pool isolation → [flash-loan.md](flash-loan.md), [oracle-manipulation.md](oracle-manipulation.md).

---

## Prevention Checklist

- [ ] All price-sensitive functions: `minOut`/`maxIn` + `deadline`
- [ ] UI default slippage reasonable; no "unlimited slippage"
- [ ] Auction/mint: commit-reveal or fixed price + allowlist + rate limit
- [ ] `approve` race documented; prefer OZ ERC20 permit
- [ ] Liquidation incentive design MEV-simulated
- [ ] Governance vote: snapshot off-chain or timelock (vote front-run)
- [ ] Integration test: attacker TX before/after in same block
- [ ] Large trades: RFQ / private relay recommendation on product side

---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Bancor front-running discussions** | 2017 | Bot front-running discussions on early DEX/on-chain market | Public security discussions / SWC-114 context |
| **Uniswap/Sushiswap sandwich industry** | 2020+ | MEV bot ecosystem; user slippage loss (not a single "CVE", systemic) | Flashbots research, academic MEV papers |
| **NFT mint sniping** | 2021– | Public mint TXs front-run by bots | Widespread incident class |
| **Liquidation MEV** | DeFi continuous | Race liquidation in lending protocols | Protocol post-mortems (Compound/Aave-class dynamics) |

SWC Registry: [SWC-114 Transaction Order Dependence](https://swcregistry.io/docs/SWC-114).  
The DAO (2016) was primarily reentrancy; don't confuse with ordering discussions — [reentrancy.md](reentrancy.md), [dao-hack-2016](case-studies/dao-hack-2016-reentrancy.md).

---

## Vibe Coding Red Flags

```
🚩 swap/liquidity: no minAmountOut parameter
🚩 deadline = type(uint).max or absent
🚩 "Fair launch mint" single TX, no limit
🚩 On-chain cleartext bid/secret
🚩 approve(spender, amount) single step, no permit
🚩 AI: "blockchain is ordered so front-run is impossible" — quite the opposite
🚩 Dependent trade in the same block as oracle update
```

### AI Prompt Snippet

```
Add minAmountOut/maxAmountIn and deadline to every swap and price-sensitive function.
Use commit-reveal for auctions or secret values.
Use increaseAllowance or EIP-2612 permit for ERC20 approval.
Assume MEV/sandwich scenario; mempool is public.
```

---

**Severity: 🟠 High** — Though not a direct "hack", it constantly leaks value; protocol insolvency in some designs.
**SWC: SWC-114** · **Refs:** [SWC-114](https://swcregistry.io/docs/SWC-114), [ConsenSys best practices — TOD](https://consensys.github.io/smart-contract-best-practices/attacks/front-running/), Flashbots / MEV research literature
