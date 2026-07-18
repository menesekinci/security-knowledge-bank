---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "What Is It?"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
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