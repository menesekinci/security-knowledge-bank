---
source: "common/engineering/security-metrics.md"
title: "📊 Security Metrics"
heading: "5. Common Pitfalls"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [building, common, common-vuln, measure, metrics, pitfalls, security]
chunk: 6/8
---

## 5. Common Pitfalls

### 1. Counting Vulns Without Context

"1,200 vulnerabilities found this month" sounds bad. But:
- Are they in the same library (one fix addresses all)?
- Are they in an unused feature?
- Are they all low-severity?

**Fix:** Always report vulns with severity distribution, affected systems, and trending direction.

### 2. Ignoring Detection Time

A team that detects incidents in 2 weeks and resolves them in 1 hour has a worse security posture than a team that detects in 5 minutes and resolves in 4 hours.

```
Posture = Detection Speed × Response Speed

Team A: MTTD = 14 days, MTTR = 1 hour → Total = 14 days + 1 hour
Team B: MTTD = 5 minutes, MTTR = 4 hours → Total = 4 hours 5 minutes
```

**Fix:** Always include MTTD alongside MTTR. MTTD is usually the bigger problem.

### 3. Measuring Activity Instead of Outcomes

| Activity Metric (Bad) | Outcome Metric (Good) |
|-----------------------|----------------------|
| Number of pentests run | Number of critical findings validated vs. remediated |
| Hours of security training delivered | % of engineers passing security competency check |
| Number of firewall rules | Number of blocked attacks on critical systems |
| Total SIEM alerts generated | Mean time to triage + resolve actionable alerts |
| Number of security tools deployed | % reduction in security debt |

**Fix:** For every activity metric, ask "and what outcome did that produce?"

### 4. Cherry-Picking Good Metrics

It's easy to show progress with metrics you're improving on. A dashboard that only shows green indicators is hiding problems.

**Fix:** Require each team/subject to show at least one red or trending-down metric. If everything is green, you're not measuring honestly.

### 5. Not Segmenting by Risk

Aggregating all vulnerabilities into a single number hides the most important signal: vulns in internet-facing, business-critical systems.

**Fix:** Always segment by:
- System criticality (Tier 1, Tier 2, Tier 3)
- Data sensitivity (PII, payment, public)
- Attack surface exposure (internet-facing, internal, isolated)

### 6. Static Dashboards That No One Reads

If your security dashboard is a PDF emailed weekly, it's already dead. People don't consume security metrics in the same way they consume application performance metrics.

**Fix:**
- Embed dashboards in existing tools (engineering uses Datadog for APM → embed security there)
- Push key metrics to Slack/Teams daily (not weekly)
- Alert on metric threshold breaches (don't wait for someone to look)
- Make the dashboard interactive (drill-down, filtering)

---