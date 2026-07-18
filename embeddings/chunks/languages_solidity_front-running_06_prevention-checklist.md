---
source: "languages/solidity/front-running.md"
title: "🟠 Front-Running & MEV"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist

- [ ] All price-sensitive functions: `minOut`/`maxIn` + `deadline`
- [ ] UI default slippage reasonable; no "unlimited slippage"
- [ ] Auction/mint: commit-reveal or fixed price + allowlist + rate limit
- [ ] `approve` race documented; prefer OZ ERC20 permit
- [ ] Liquidation incentive design MEV-simulated
- [ ] Governance vote: snapshot off-chain or timelock (vote front-run)
- [ ] Integration test: attacker TX before/after in same block
- [ ] Large trades: RFQ / private relay recommendation on product side

---