---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "3. Risk Treatment Options"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 4/9
---

## 3. Risk Treatment Options

Every risk gets one of four treatments. "Ignore it" is not an option — if you do nothing, you've implicitly accepted it.

| Option | What It Means | Example |
|---|---|---|
| **Avoid** | Remove the risk by eliminating the feature, component, or activity. | "We won't store credit card numbers — we'll use a tokenization provider instead." |
| **Mitigate** | Add controls to reduce likelihood, impact, or both. | "We can't eliminate phishing, but MFA reduces the impact of credential theft by 99%." |
| **Transfer** | Shift the financial burden to a third party. | Cyber insurance, third-party liability clauses in vendor contracts. |
| **Accept** | Acknowledge the risk explicitly and choose not to act, with documented approval. | Low-severity risk in a non-critical system, approved by the product owner. |

### 3.1 Mitigation Depth

When mitigating, you have two levers:

| Lever | How it works | Example |
|---|---|---|
| **Reduce Likelihood** | Make the attack harder to execute | WAF blocking SQLi, rate limiting, employee security training |
| **Reduce Impact** | Contain the blast radius | Network segmentation, least-privilege IAM, encryption at rest |

**Defense in depth** applies both levers simultaneously. A single control can be bypassed; layered controls make bypass exponentially harder.

### 3.2 Risk Acceptance — The Right Way

Risk acceptance is legitimate but must be deliberate:

1. **Document the risk** — what it is, why it's being accepted, who decided.
2. **Set a review date** — accept for a fixed period, not indefinitely. Conditions change.
3. **Require appropriate authority** — low risks: engineering manager. Medium: director/VIP. High/Critical: CISO or board.
4. **Track in your risk register** — accepted risks are still risks; they need monitoring.

**Anti-pattern:** "We accept the risk" as code for "we don't have time to fix this." Real acceptance requires a named decision-maker, a written rationale, and a timer.

---