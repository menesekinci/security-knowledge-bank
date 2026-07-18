---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] Grep for `block.timestamp` / `blockhash` / `prevrandao` used for "random"
- [ ] Gambling/lottery: VRF or commit-reveal present?
- [ ] Are randomness and payout in the **same TX**? (critical anti-pattern)
- [ ] Can attacker's contract cancel losing attempts via `revert`?
- [ ] NFT rarity: reveal phase separate; metadata pre-image commit
- [ ] Economic test: EV of grinding / simulation attack
- [ ] Documentation: randomness trust model clearly stated

---