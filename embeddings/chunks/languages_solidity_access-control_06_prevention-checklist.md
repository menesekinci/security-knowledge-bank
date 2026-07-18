---
source: "languages/solidity/access-control.md"
title: "🟠 Access Control Vulnerabilities"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "critical"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] Every state-changing function: who can call it? Make a table
- [ ] Do `public`/`external` admin functions have modifiers?
- [ ] Grep for `initialize` / `init` / `setup` → initializer protection
- [ ] Ownership: Ownable2Step or multi-sig; single EOA risk accepted in writing
- [ ] Role hierarchy: DEFAULT_ADMIN in separate cold wallet
- [ ] `delegatecall` / proxy admin in separate contract ([delegatecall-proxy.md](delegatecall-proxy.md))
- [ ] Slither `unprotected-upgrade`, `naming-convention` (constructor)
- [ ] Fork test: attacker EOA calling `withdraw`/`mint`/`upgrade` should revert
- [ ] Emergency pause in separate role; unpause more restrictive

---