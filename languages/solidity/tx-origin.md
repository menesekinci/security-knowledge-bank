# 🔴 Solidity tx.origin vs msg.sender

## What Is It?
`tx.origin` is the **first** address that initiated the transaction, while `msg.sender` is the **last** caller.
Using `tx.origin` allows a contract to perform transactions on your behalf.

## Example
```solidity
// 💀 VULNERABLE:
function withdrawAll() public {
    require(tx.origin == owner);  // Don't use tx.origin!
    payable(owner).transfer(address(this).balance);
}
// Attacker:
// 1. Tricks owner into calling a malicious contract
// 2. That contract calls withdrawAll()
// 3. tx.origin == owner (owner initiated it) → True! 💀

// ✅ SECURE:
function withdrawAll() public {
    require(msg.sender == owner);  // Controls the last caller
    payable(owner).transfer(address(this).balance);
}
```

## Rule
**NEVER** use `tx.origin`. Always use `msg.sender`.
The only case where you might use `tx.origin`: not in the `onlyOwner` modifier.

---

**Severity: 🔴 Critical** — Unauthorized access.
**SWC: SWC-115**
