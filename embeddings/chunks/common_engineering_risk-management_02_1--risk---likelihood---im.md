---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "1. Risk = Likelihood × Impact — What This Means in Practice"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 2/9
---

## 1. Risk = Likelihood × Impact — What This Means in Practice

The canonical formula is deceptively simple. In engineering practice:

**Likelihood** — How probable is it that a given threat will exploit a vulnerability? This is not a guess; it should be informed by:
- Historical incident data from your own organization
- Industry breach reports (Verizon DBIR, CrowdStrike Threat Report)
- Attack prevalence in your threat landscape (e.g., if you run a public web app, credential stuffing is *high* likelihood)
- Existing control strength (if you have MFA enforced everywhere, credential theft likelihood drops)

**Impact** — What's the worst realistic outcome? Measured in:
- Financial loss (direct theft, remediation cost, regulatory fines)
- Data exposure (records compromised, sensitivity level)
- Operational disruption (downtime, degraded performance)
- Reputational damage (customer trust, stock price, brand equity)
- Legal liability (class action, GDPR penalties up to 4% of global revenue)

**The practical trap:** Teams treat likelihood and impact as abstract labels. To make risk actionable, anchor each rating to specific, measurable criteria:

```
Likelihood: High = >1 incident per year in comparable orgs
Impact: Critical = >$1M expected loss OR >100K PII records exposed
```

Without anchors, two engineers can arrive at opposite risk ratings for the same scenario because one thinks "that won't happen to us" and the other thinks "if it does, we're dead." Anchors force alignment based on evidence, not gut feel.

---