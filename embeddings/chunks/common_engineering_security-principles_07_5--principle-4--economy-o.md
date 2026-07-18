---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "5. Principle 4: Economy of Mechanism"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 7/14
---

## 5. Principle 4: Economy of Mechanism

**"Keep the design as simple and small as possible. Complexity is the enemy of security."**

### What It Means

Every line of code, every configuration knob, every integration point is an opportunity for a vulnerability. Smaller, simpler designs have fewer bugs, are easier to audit, and are more likely to be correctly implemented.

### The Complexity-Vulnerability Curve

```
Vulnerability Density
        ↑
        |                       /
        |                     /
        |                   /
        |                 /
        |               /
        |             /
        |           /
        |─────────/─────── Complex baseline
        |         /
        |       /
        |     /
        |   /
        | /
        +──────────────────────────→ Code/Config Complexity
```

### Real-World Engineering Scenario

**Scenario:** Two approaches to authorization middleware.

**Complex approach:** A custom rules engine that evaluates user attributes, resource tags, time windows, and geolocation via a JSON DSL with 14 different operators. Six engineers maintain 9,000 lines of evaluator code. Three bugs found in production in the last quarter — two were bypassable.

**Simple approach:** Four well-defined roles with explicit allow-lists. The policy is 200 lines of configuration. Any engineer can read it and verify correctness. Extensions are rare and reviewed in depth.

The simpler system is not only easier to secure — it is actually more *capable* because its correctness is verifiable.

### Practical Tactics

- Prefer **whitelists** over blacklists (you can enumerate what's allowed, but never what's forbidden)
- Choose **well-audited frameworks** over custom implementations (don't write your own crypto, auth, or serialization)
- **Remove dead code** — every unused endpoint, feature flag, and config parameter is a potential attack surface
- **Composability over monoliths** — small single-purpose components are easier to reason about

---