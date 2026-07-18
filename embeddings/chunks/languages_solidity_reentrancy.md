---
source: "languages/solidity/reentrancy.md"
title: "🔴 Reentrancy Attack"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [code, does, language-vuln, prevention, secure, solidity, what]
---

# 🔴 Reentrancy Attack

## What Is It?

When a contract sends funds to an external contract, that contract's `receive()` or `fallback()` function **calls you again** and withdraws more funds before you have updated your state. The most classic blockchain vulnerability.

## Why Does It Occur Frequently in Vibe Coding?

```
Prompt: "Write a withdrawal function, send user their balance"
AI wrote:
```

```solidity
// 💀 VULNERABLE — Open to reentrancy
function withdraw(uint _amount) public {
    require(balances[msg.sender] >= _amount);
    
    (bool sent, ) = msg.sender.call{value: _amount}("");  // SEND first
    require(sent, "Failed to send");
    
    balances[msg.sender] -= _amount;  // THEN update — 💀
}
```

## How Does It Work?

```
1. Attacker calls withdraw(1 ETH)
2. Contract sends 1 ETH → Attacker's contract receives via receive()
3. Inside receive(), calls withdraw(1 ETH) AGAIN
4. Contract's balances[attacker] is still >= 1 ETH (not updated yet!)
5. Steps 2-4 repeat → until all funds are drained 💀

DAO Hack (2016): 3.6 million ETH ($60M+) stolen this way.
```

## Secure Code

```solidity
// ✅ Checks-Effects-Interactions pattern:
function withdraw(uint _amount) public {
    // 1. CHECKS
    require(balances[msg.sender] >= _amount);
    
    // 2. EFFECTS (update state first!)
    balances[msg.sender] -= _amount;
    
    // 3. INTERACTIONS (external call last)
    (bool sent, ) = msg.sender.call{value: _amount}("");
    require(sent, "Failed to send");
}

// ✅ Or OpenZeppelin ReentrancyGuard:
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MyContract is ReentrancyGuard {
    function withdraw(uint _amount) public nonReentrant {
        require(balances[msg.sender] >= _amount);
        balances[msg.sender] -= _amount;
        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent, "Failed to send");
    }
}
```

## Prevention

| Rule | Description |
|------|-------------|
| **Checks-Effects-Interactions** | Update state first, then make external calls |
| **ReentrancyGuard** | OpenZeppelin's ready-made solution |
| **use transfer() instead of call()** | 2300 gas limit (legacy, but additional protection) |
| **Mark all external calls** | Which functions make external calls? |

## Critical Rule for Vibe Coding
```
In Solidity, always update state BEFORE every external call.
Never violate this rule. Import ReentrancyGuard.
```

## Real World Incidents
- **DAO Hack (2016)**: $60M+ loss, led to Ethereum fork
- **Uniswap/Lendf.Me (2020)**: $25M reentrancy attack
- **Cream Finance (Aug 2021)**: ~$18.8M reentrancy via the AMP token's ERC-777 `tokensReceived` hook (the separate $130M Oct 2021 Cream hack was price-oracle/flash-loan manipulation, NOT reentrancy)
- **Fei Protocol (2022)**: $80M reentrancy attack

---

**Severity: 🔴 Critical** — Can drain all funds from the contract.
**SWC: SWC-107 (Reentrancy)**
