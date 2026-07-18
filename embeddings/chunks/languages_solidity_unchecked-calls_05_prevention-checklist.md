---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "Prevention Checklist"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 5/7
---

## Prevention Checklist

- [ ] grep `\.send\(` and `\.call\{` — every one has `require(ok)` or an OZ helper
- [ ] ERC20 outflows use SafeERC20
- [ ] Fee-on-transfer / rebasing token assumptions are covered in tests
- [ ] CEI ordering: state → interaction
- [ ] ReentrancyGuard on sensitive withdraw paths
- [ ] Fail path: are the event + accounting consistent (no double payment / loss)?
- [ ] If try/catch is used, ban empty catch blocks
- [ ] Slither `unchecked-transfer`, `low-level-calls`

---