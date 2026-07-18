---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 onlyOwner in comment but not in code
🚩 function setOwner / setAdmin / mint / upgrade — no modifiers
🚩 initialize() public, no Initializable
🚩 owner = tx.origin or tx.origin == owner
🚩 Single private key admin + unlimited mint
🚩 AI custom Ownable (no event/zero-address/2-step)
🚩 selfdestruct or delegatecall public
🚩 Logic assumed "internal" is actually public
```

### AI prompt snippet

```
Use OpenZeppelin Ownable2Step and/or AccessControl.
Add the correct modifier to all admin/mint/pause/upgrade/withdraw functions.
Use msg.sender; tx.origin is forbidden.
If upgradeable, use Initializable + _disableInitializers() in constructor.
Least privilege: minter != admin. Events are mandatory.
```

---

**Severity: 🔴 Critical** — Unprotected withdraw/mint/upgrade = protocol takeover.
**SWC: SWC-105 / SWC-106** (+ SWC-115) · **Refs:** [SWC-105](https://swcregistry.io/docs/SWC-105), [SWC-106](https://swcregistry.io/docs/SWC-106), [OpenZeppelin Access](https://docs.openzeppelin.com/contracts/5.x/access-control)