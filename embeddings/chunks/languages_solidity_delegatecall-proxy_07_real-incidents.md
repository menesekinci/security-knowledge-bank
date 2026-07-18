---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "Real Incidents"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 7/8
---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Parity multi-sig / library** | 2017 | Library ownership + `delegatecall` pattern → wallet freeze / drain class events | Public post-mortems, SWC-112 context |
| **Uninitialized proxy/implementation wave** | 2020– | Initialize front-run on various protocols | Audit findings (OpenZeppelin guidance) |
| **Audius governance** | 2022 | Proxy/governance storage & upgrade related critical issue (community post-mortem) | Public Audius incident reports |
| **Wormhole** | 2022 | Primary vector signature/sysaccount — lesson on bridge/proxy trust surface | [wormhole-bridge-2022-signature-bypass.md](case-studies/wormhole-bridge-2022-signature-bypass.md) |

Refs: [SWC-112](https://swcregistry.io/docs/SWC-112), [OpenZeppelin Proxy docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies), [UUPS](https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable).

---