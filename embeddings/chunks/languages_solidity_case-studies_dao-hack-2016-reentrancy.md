---
source: "languages/solidity/case-studies/dao-hack-2016-reentrancy.md"
title: "DAO Hack (2016) — Solidity Reentrancy"
category: "case-study"
language: "solidity"
severity: "critical"
tags: [case-study, cause, happened, impact, root, solidity, system, target, what, when]
---

# DAO Hack (2016) — Solidity Reentrancy

## 📅 When Did It Happen?
June 17, 2016

## 🎯 Target System
The DAO — a decentralized autonomous organization on Ethereum (smart contract). It had raised approximately $150M worth of ETH.

## 🔴 What Happened?
An attacker drained funds using a **reentrancy** vulnerability in the DAO contract.
- The DAO's `withdraw()` function **sent ETH first, then updated the balance**
- The attacker's contract called `withdraw()` again inside `receive()`
- Since the balance was never decreased, withdrawals could be made repeatedly
- **3.6 million ETH** (~$60M at the time) was stolen

## 🧠 Root Cause
```solidity
// VULNERABLE:
function withdraw(uint _amount) public {
    require(balances[msg.sender] >= _amount);
    
    // Send FIRST
    msg.sender.call.value(_amount)();  
    
    // Update AFTER — too late!
    balances[msg.sender] -= _amount;
}
```

## 💥 Impact
- Ethereum **forked** (ETH vs ETC)
- Crypto community split in two
- $60M+ loss (value at the time)
- Launched smart contract security awareness across the entire crypto world

## 🔧 How Was It Fixed?
1. Ethereum blockchain underwent a **hard fork** (block #1,920,000)
2. Funds were returned to original owners via the fork
3. Ethereum Classic (ETC) was created by those who rejected the fork
4. `ReentrancyGuard` pattern was added to Solidity

## 🎓 Lessons Learned
- **Always apply the Checks-Effects-Interactions pattern**
- **Update state first**, then make external calls
- **Use ReentrancyGuard** (OpenZeppelin)
- External calls are always dangerous

## Vibe Coding Connection
When writing Solidity with AI:
- AI frequently produces the "send first, update later" pattern
- Always use the `nonReentrant` modifier
- Add the Checks-Effects-Interactions rule to your prompt

## 🔗 Source
- https://www.coindesk.com/understanding-dao-hack-journalists
- SWC-107 (Reentrancy): https://swcregistry.io/docs/SWC-107
