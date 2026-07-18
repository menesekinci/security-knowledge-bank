# 🔷 Solidity / Blockchain Security Hardening Checklist

> Items to verify in every smart contract project before deployment.

## ✅ Reentrancy
- [ ] Is the Checks-Effects-Interactions pattern applied?
- [ ] Is `ReentrancyGuard` (OpenZeppelin) used?
- [ ] Have all external calls been flagged?

## ✅ Access Control
- [ ] Are `onlyOwner` / `onlyRole` modifiers present on every function?
- [ ] Is `tx.origin` avoided? (Is `msg.sender` used instead?)
- [ ] Is OpenZeppelin's Ownable / AccessControl used?

## ✅ Math
- [ ] Is there integer overflow/underflow protection? (Solidity ^0.8 default)
- [ ] Is SafeMath used? (for older versions)
- [ ] Are `unchecked` blocks justified?

## ✅ Oracle & Price Feeds
- [ ] Is Chainlink used? (not a single source)
- [ ] Is TWAP (Time-Weighted Average Price) used?
- [ ] Is price feed freshness checked?
- [ ] Is there a circuit breaker?

## ✅ External Calls
- [ ] Are all `call{value:}` results checked?
- [ ] Was the gas limit checked? (for loop + external call)
- [ ] Are `transfer()` / `send()` return values checked?

## ✅ Randomness
- [ ] `block.timestamp`, `blockhash`, `block.difficulty` are NOT a source of randomness!
- [ ] Is Chainlink VRF used?
- [ ] Is a commit-reveal scheme used?

## ✅ Audit
- [ ] Was a professional audit performed? (Trail of Bits, ConsenSys, OpenZeppelin)
- [ ] Is test coverage 100%?
- [ ] Was Slither / Mythril static analysis run?
- [ ] Was a bug bounty program launched?

## 🛡️ Vibe Coding Extra
- [ ] Was the AI-written contract ALWAYS audited?
- [ ] Was the AI's use of `tx.origin` replaced with `msg.sender`?
- [ ] Was the AI's reentrancy vulnerability checked?
