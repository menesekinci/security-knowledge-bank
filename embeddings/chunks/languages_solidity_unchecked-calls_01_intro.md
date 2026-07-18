---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "intro"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 1/7
---

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