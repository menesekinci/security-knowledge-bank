---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "5. Building a Risk Register"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 6/9
---

## 5. Building a Risk Register

A risk register is the single source of truth for your organization's security risks. It's not a static document — it's a living tool for prioritization and decision-making.

### What Goes In

| Field | Description | Example |
|---|---|---|
| **Risk ID** | Unique identifier | RISK-0042 |
| **Description** | Clear, one-paragraph scenario | "Attacker exploits our unpatched API gateway to access the user database" |
| **Category** | Type of risk | Application Security, Infrastructure, Third-Party, Compliance |
| **Asset** | What's at risk | User database (PostgreSQL, prod) |
| **Threat** | Who/what could cause it | External attacker, automated scanning |
| **Vulnerability** | The weakness | API gateway is 3 versions behind on patches |
| **Likelihood** | L/M/H or quantitative | Medium (3/5) |
| **Impact** | L/M/H or quantitative | High (4/5) |
| **Inherent Risk** | Risk before controls | High |
| **Controls** | Existing mitigations | WAF in front, network segmentation |
| **Residual Risk** | Risk after controls | Medium |
| **Treatment** | Avoid/Mitigate/Transfer/Accept | Mitigate |
| **Owner** | Person responsible | eng-lead@ |
| **Review Date** | When to reassess | 2026-01-15 |

### How to Prioritize

Simple heuristic for triage:
1. **Critical risks** (likely + catastrophic): freeze, escalate, fix immediately.
2. **High risks**: assigned to an owner with a 30-day remediation target.
3. **Medium risks**: added to the backlog, reviewed quarterly.
4. **Low risks**: accepted or scheduled for next major release.

For quantitative registers, sort by ALE (highest expected annual loss first). This surfaces which risks deserve investment.

### How to Review

- **Monthly:** Review new risks and high-risk mitigations.
- **Quarterly:** Full register review — reassess likelihood/impact, close old risks, add new ones.
- **Annually:** Deep audit — validate that the register covers the entire threat landscape (new products, new compliance requirements, new attack vectors).

**Anti-pattern:** A 200-item risk register that no one looks at. If you have more risks than you can act on, you're not prioritizing — you're hoarding. Archive risks rated Low/Medium with accepted treatments and focus on the top 20.

---