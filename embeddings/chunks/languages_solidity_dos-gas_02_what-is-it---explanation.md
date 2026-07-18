---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "What Is It? (Explanation)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 2/8
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