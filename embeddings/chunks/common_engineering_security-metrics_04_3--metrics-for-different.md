---
source: "common/engineering/security-metrics.md"
title: "📊 Security Metrics"
heading: "3. Metrics for Different Audiences"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [building, common, common-vuln, measure, metrics, pitfalls, security]
chunk: 4/8
---

## 3. Metrics for Different Audiences

Different stakeholders need different metrics. Giving executives vulnerability counts is noise. Giving engineers compliance scores is irrelevant.

### Engineering Team

*Focus: actionable, within-team-control metrics*

| Metric | Why It Matters | Target |
|--------|---------------|--------|
| Critical vulns opened this sprint | Team workload view | Track per sprint |
| Critical vulns closed this sprint | Team velocity | Close rate > open rate |
| Scan pass rate in CI | Quality gate effectiveness | > 95% |
| Mean time to fix PR-identified vulns | Developer responsiveness | < 24 hours |
| Security test coverage | Test quality | > 80% of critical paths |
| False positive rate | Tool noise impact | < 20% |

**Best format:** Per-team dashboard showing weekly trends. Single number: "Fixes this week" with red/yellow/green.

### Management / Security Leadership

*Focus: risk trends, operational health, resource allocation*

| Metric | Why It Matters | Target |
|--------|---------------|--------|
| Open vulns by severity over time | Trend direction | Decreasing |
| MTTP by severity | Speed of remediation | Within SLA |
| Security debt score | Cumulative risk | Decreasing |
| Scan coverage by tool | Tooling gaps | 100% |
| Incident count + severity distribution | Attack surface trend | Stable or decreasing |
| Budget vs. spend per control area | Resource efficiency | Within budget |

**Best format:** Monthly report with trend lines (last 12 months). Top 3 risks highlighted. No raw counts — use per-KLOC or per-service normalized figures.

### Executives / Board

*Focus: business impact, breach likelihood, compliance, ROI*

| Metric | Why It Matters | Target |
|--------|---------------|--------|
| Breach likelihood (next 12 months) | Risk appetite alignment | Per board threshold |
| Estimated financial impact of top risks | Business continuity | Within tolerance |
| Compliance status (SOC 2, ISO 27001, PCI) | Customer trust + revenue | In good standing |
| Incident count (total + with customer impact) | Brand reputation | Trending down |
| Security spend as % of IT/engineering budget | Cost efficiency | Industry benchmark |
| Time to detect + respond to critical incidents | Operational maturity | Improving YoY |

**Best format:** Quarterly board deck with 5–7 KPIs. Traffic-light (Red/Yellow/Green). One-paragraph narrative for each KPI. No engineering jargon.

---