---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "6. Communication: How to Talk to Non-Security Stakeholders"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 7/9
---

## 6. Communication: How to Talk to Non-Security Stakeholders

Security engineers and business stakeholders often speak different languages. Here's how to bridge the gap.

### Translate Security into Business Terms

| Don't Say | Do Say |
|---|---|
| "We have a critical RCE vulnerability in the auth service" | "If we don't patch this, an attacker could take over user accounts. Estimated cost of a breach: $1-3M." |
| "We need to implement network segmentation" | "Segmentation limits the damage from a breach — from 'all systems down for a week' to 'one subsystem down for a day.' This saves us ~$2M per incident." |
| "The risk register has 47 high-severity items" | "Our top 3 risks this quarter account for $4M in potential exposure. Here's the plan for each." |
| "We need more budget for AppSec" | "For $150K/year (one security engineer), we can reduce our most likely breach scenario by 60%. ROl: 3:1 in year one." |

### Framing for Different Audiences

| Audience | What They Care About | Your Language |
|---|---|---|
| **Engineering team** | Technical specifics, action items | CVEs, versions, code paths, PRs |
| **Engineering director** | Schedule impact, resource needs | "2 sprints to patch, 1 eng assigned" |
| **CISO** | Control effectiveness, compliance posture | Risk reduction %, audit readiness |
| **CFO / Board** | Financial exposure, ROI | ALE, cost of controls, insurance impact |
| **Legal** | Liability, regulatory risk | GDPR fines, breach notification obligations |

### The One-Page Risk Summary

For executive reporting, a single page containing:
1. **Top 5 risks** — ranked by residual risk, with treatment status
2. **Trend** — is risk going up or down quarter-over-quarter?
3. **Hot topics** — new threats, incidents at similar companies
4. **Ask** — what do you need from them? (budget, decision, policy)

---