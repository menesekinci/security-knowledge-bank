---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "10. Common Mistakes"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 12/13
---

## 10. Common Mistakes

### Mistake 1: Threat Modeling Too Late

Waiting until the system is built to threat model means the design is already locked in. Findings become "won't fix" because refactoring is too expensive. **Do it during design, not after implementation.**

### Mistake 2: Analysis Paralysis

Trying to enumerate *every possible* threat leads to a 200-item threat list that nobody reads. A threat model with 20 well-prioritized threats is more useful than one with 200 unprioritized ones. **Focus on the top 5–10 critical threats first.**

### Mistake 3: Ignoring Human Elements

Threat models often assume rational, technical attackers. Real-world attack chains include social engineering, insider threats, and operational mistakes. **Include "operator error" and "insider" as threat actors.**

### Mistake 4: One-and-Done

A threat model is a living document. As the system evolves — new features, new dependencies, new deployment model — the threat model must evolve too. **Treat threat models like code: versioned, reviewed, updated.**

### Mistake 5: Only Thinking About External Attackers

Many damaging attacks come from insiders or from compromised third-party dependencies. Your threat model should include threat actors at every trust level: anonymous user, authenticated user, partner integration, employee, contractor, system administrator.

### Mistake 6: Not Validating Mitigations

"If we use JWT, it's secure" — but is the JWT library correctly configured? Is the signing key rotated? Are revoked tokens checked? **A mitigation in a threat model is a hypothesis until it is tested.**

### Mistake 7: Document Dumps

Putting the threat model in a PDF that lives in a wiki folder nobody visits means it has no effect. **The threat model should directly drive backlog items, test cases, and architecture decisions.**

### Mistake 8: Over-Focusing on Technology

Threat models that only consider technical controls (encryption, auth) but ignore process controls (incident response, access reviews, training) miss half the picture. **Include operational and procedural threats.**

---