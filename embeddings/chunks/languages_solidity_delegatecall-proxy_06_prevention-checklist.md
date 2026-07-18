---
source: "languages/solidity/delegatecall-proxy.md"
title: "🟡 Delegatecall & Proxy Storage Risks"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] `delegatecall` grep — target constant / whitelist / OZ proxy only?
- [ ] Implementation `initialize` + `_disableInitializers`
- [ ] Storage layout: `forge inspect` / OZ storage check V1 vs V2
- [ ] `__gap` or namespaced storage
- [ ] Upgrade path: onlyOwner/AccessControl + timelock
- [ ] Implementation contract self-call attack test (init)
- [ ] No `selfdestruct` in logic used via delegatecall
- [ ] Slither `controlled-delegatecall`, `unprotected-upgrade`
- [ ] Wormhole-class: don't confuse guardian/sig verification with proxy admin — separate threat model

---