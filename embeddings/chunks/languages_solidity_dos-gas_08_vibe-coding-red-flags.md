---
source: "languages/solidity/dos-gas.md"
title: "🟡 Denial of Service via Gas (DoS)"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 for (i < array.length) { payable(x).transfer }
🚩 distribute / payoutAll / refundAll single TX
🚩 previous.transfer inside bid()
🚩 "require(success)" to foreign address inside batch
🚩 No MAX_BATCH; AI processes "all at once"
🚩 Deletion: while(array.length>0) pop + external
🚩 Assumption that gas limit is "high enough"
```

### AI Prompt Snippet

```
Use pull-over-push for payments; mapping pending + withdraw.
Never make external calls inside an unbounded loop.
Use MAX_BATCH limit and cursor for batch operations.
Reverting receiver should not lock the entire protocol.
Checks-Effects-Interactions + ReentrancyGuard.
```

---

**Severity: 🟡–🟠** — Funds can be locked without being stolen; governance/auction paralysis.
**SWC: SWC-128** · **Refs:** [SWC Registry SWC-128](https://swcregistry.io/docs/SWC-128), OpenZeppelin payment/pull patterns in docs & examples