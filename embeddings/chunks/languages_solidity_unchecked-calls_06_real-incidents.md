---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "Real Incidents"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 6/7
---

## Real Incidents

| Incident | Year | Summary | Source |
|------|-----|------|--------|
| **King of the Ether / early games** | ~2016 | `send` fail / gas stipend breaking crown/payout logic | Historical analyses, SWC-104 class |
| **SWC-104 canonical samples** | — | `callee.call()` unchecked | [SWC-104](https://swcregistry.io/docs/SWC-104) |
| **USDT-class ERC20 quirks** | continuous | Non-standard return → integration failure or false trust | OpenZeppelin SafeERC20 rationale |
| **Batch bridges / multisend bugs** | various audits | Partial call fail ignored → accounting desync | Public audit reports (pattern class) |

The DAO Hack is primarily tied to reentrancy + call usage; the **CEI violation** stands out more than the return value — but the low-level `call` surface is common to both: [reentrancy.md](reentrancy.md), [dao-hack-2016](case-studies/dao-hack-2016-reentrancy.md).

---