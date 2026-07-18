---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "11. Applying Principles Together"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 13/14
---

## 11. Applying Principles Together

No principle operates in isolation. They interact — sometimes reinforcing, sometimes conflicting. The art of security engineering is balancing them.

### Tensions

| Principles | Tension | Resolution |
|---|---|---|
| Least Privilege vs Psychological Acceptability | Strict permissions frustrate users | Use JIT elevation — access is restricted by default but easy to request temporarily |
| Economy of Mechanism vs Defense in Depth | Simplicity says one control; layered defense says many | Layer different *kinds* of controls, not redundant copies of the same one |
| Complete Mediation vs Performance | Checking every access is slow | Cache authorization decisions for short TTLs and invalidate on permission changes |
| Open Design vs Least Common Mechanism | Open APIs are shared by nature | Design APIs with per-tenant isolation and explicit scopes |

### Decision Heuristic

When evaluating a security design decision, ask:

1. **Which principles does this decision honor?** (List them.)
2. **Which principles does this decision violate?** (Be honest — no design is perfect.)
3. **Is the violation explicit and documented?** (It should be in an ADR or design doc.)
4. **Is the violation mitigated by another principle?** (E.g., violating Economy of Mechanism with a more complex authorization layer might be justified by Least Privilege requirements.)
5. **What is the residual risk after all mitigations?** (No design eliminates all risk — know what's left.)

---