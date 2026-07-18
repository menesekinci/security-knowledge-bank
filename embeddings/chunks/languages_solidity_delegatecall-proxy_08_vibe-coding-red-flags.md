---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 8/8
---

## Vibe Coding Red Flags

```
🚩 delegatecall(userAddress, ...)
🚩 No storage gap in upgradeable contract
🚩 Variable order changed in V2
🚩 initialize public, no _disableInitializers
🚩 upgradeTo open to everyone
🚩 AI custom proxy (no OZ)
🚩 Blindly delegatecall'ing msg.data
🚩 Assuming constructor state + proxy state are mixed
🚩 Comment saying "delegatecall = call"
```

### AI prompt snippet

```
For upgradeable: use OpenZeppelin UUPS/Transparent + Upgrades plugin.
No delegatecall to user input.
_disableInitializers() in implementation constructor.
Storage only appended at the end; gap or EIP-7201 namespace.
_authorizeUpgrade onlyOwner/multi-sig. Run validateUpgrade.
```

---

**Severity: 🔴 Critical** — A single bad `delegatecall` or storage collision = full storage write / protocol takeover.
**SWC: SWC-112** · **Refs:** [SWC-112](https://swcregistry.io/docs/SWC-112), [OZ Proxies](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies), [SWC Registry](https://swcregistry.io/)