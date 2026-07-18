---
source: "languages/solidity/case-studies/poly-network-2021-610m-hack.md"
title: "Poly Network Hack (2021) — Cross-Chain Access Control / Forged Function Selector"
category: "case-study"
language: "solidity"
severity: "critical"
tags: [case-study, cause, happened, impact, root, solidity, system, target, what, when]
---

# Poly Network Hack (2021) — Cross-Chain Access Control / Forged Function Selector

## 📅 When Did It Happen?
August 10, 2021

## 🎯 Target System
Poly Network — cross-chain bridge protocol (asset transfer between Ethereum, Binance Smart Chain, Polygon)

## 🔴 What Happened?
An attacker stole roughly **$611M** worth of crypto assets using a vulnerability in Poly Network's cross-chain smart contracts.
- Root cause was an **access-control failure**, NOT reentrancy
- Millions of dollars in a single transaction

The most interesting aspect of this hack: **The attacker later returned all the funds!**

## 🧠 Root Cause
The real mechanism was a **forged function-selector / access-control bypass** in the `EthCrossChainManager` contract.

- `EthCrossChainManager` is the owner of the `EthCrossChainData` contract, so it is the only contract allowed to change the trusted "keeper" (guardian) public keys — via `putCurEpochConPubKeyBytes`.
- The manager's `verifyHeaderAndExecuteTx` → `_executeCrossChainTx` path let a cross-chain message dispatch a call to a target contract by a short (4-byte / 32-bit) method ID derived from `keccak256(_method)`.
- The attacker **brute-forced a `_method` string whose keccak hash collided with the 32-bit selector of `putCurEpochConPubKeyBytes`**. This let them route a call to that privileged function even though it was never meant to be reachable cross-chain.
- Result: the attacker **replaced the keeper/guardian public keys with their own**, then signed and approved arbitrary withdrawals — draining the bridge.

```solidity
// Simplified: the manager dispatches by a hashed method id, no access check on WHICH function is hit.
function _executeCrossChainTx(address toContract, bytes memory method, bytes memory args) internal {
    // Selector derived from keccak of the caller-supplied method name (only 32 bits checked)
    bytes memory sig = abi.encodePacked(bytes4(keccak256(abi.encodePacked(method, "(bytes,bytes,uint64)"))), args);

    // Attacker brute-forced `method` so this selector EQUALS putCurEpochConPubKeyBytes'.
    // => arbitrary privileged call: replace the keeper/guardian public keys!
    (bool ok, ) = toContract.call(sig);  // Forged selector -> access control bypass
    require(ok);
}
```

## 💥 Impact
- ~$611M stolen (one of the biggest DeFi hacks ever)
- All funds returned within 3 days (attacker said "I did it for fun")
- Cross-chain bridge security brought into question

## 🧠 Attacker's Story
The attacker said in on-chain messages:
- "I found it by chance while researching another project's security vulnerability"
- "I was going to borrow the funds and return them"
- "I wish there was a DAO structure that would reward this hack"

## 🎓 Lessons Learned
- **Cross-chain bridge = most risky DeFi** — you rely on the security of multiple blockchains
- **Access control** must be checked on every function
- **External calls** are always dangerous
- Even audit firms had missed this vulnerability (it had passed 2 audits)

## Vibe Coding Connection
When writing Solidity with AI:
- Cross-chain logic is complex; AI usually skips access control
- Verify that every public function has `onlyOwner` or authorization check
- Don't forget state updates before external calls

## 🔗 Source
- https://poly.network/
- https://rekt.news/poly-network-hack/
