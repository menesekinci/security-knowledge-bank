---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 7/7
---

## Vibe Coding Red Flags

```
🚩 .send( without if/require
🚩 (bool ok,) = ...call; and ok is never used
🚩 token.transfer / transferFrom with no SafeERC20
🚩 balances=0 then unchecked send
🚩 AI: "call always returns true"
🚩 empty catch {} on external call
🚩 success ignored + "paid" event
🚩 assuming a modern recipient contract with a 2300 gas transfer
```

### AI prompt snippet

```
Check every low-level call/send result with require.
For ETH use Address.sendValue or call+require.
For ERC20 use OpenZeppelin SafeERC20.
Checks-Effects-Interactions + ReentrancyGuard.
Do not update state as a "successful payment" when it fails.
```

---

**Severity: 🟡–🟠** — Silent payment failure → user loss of funds or accounting exploit.
**SWC: SWC-104** · **Refs:** [SWC-104](https://swcregistry.io/docs/SWC-104), [ConsenSys — external calls](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/), [OpenZeppelin SafeERC20](https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#SafeERC20), [Address.sendValue](https://docs.openzeppelin.com/contracts/5.x/api/utils#Address)