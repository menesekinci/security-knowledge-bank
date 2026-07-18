---
source: "common/engineering/security-metrics.md"
title: "📊 Security Metrics"
heading: "4. Building a Security Dashboard"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [building, common, common-vuln, measure, metrics, pitfalls, security]
chunk: 5/8
---

## 4. Building a Security Dashboard

### What to Track

A well-designed security dashboard has three layers:

```
LAYER 1: HEALTH (Top-level, always visible)
├── Incident status (active incidents count + severity)
├── Critical vulns (open count, age of oldest)
├── Compliance posture (% of controls passing)
└── Scanning coverage (% of repos covered)

LAYER 2: TRENDS (Weekly/Monthly view)
├── MTTD / MTTR trend (last 12 weeks)
├── MTTP by severity (last 12 weeks)
├── Vuln discovery vs. fix rate (last 12 months)
└── Security debt score (last 12 months)

LAYER 3: DEEP DIVE (Drill-down from Layer 2)
├── Per-service vuln density
├── Per-team fix velocity
├── Top 10 longest-open vulns
├── False positive rate by tool
└── Attack surface changes (new endpoints, new repos)
```

### Tooling Options

| Tool | Best For | Cost |
|------|----------|------|
| **Grafana** | Custom dashboards, mixed data sources (Prometheus, Loki, Elastic) | Open-source / Cloud paid |
| **AWS Security Lake** | Centralized security data lake for AWS-native orgs | Per-GB pricing |
| **Snyk Reports** | Application security + dependency metrics | Included with Snyk |
| **Datadog Security** | Cloud SIEM + dashboards in one platform | Per-host pricing |
| **Elastic Security** | SIEM + dashboards, self-hosted or cloud | Open-source / Cloud paid |
| **Google Security Command Center** | GCP-native security posture dashboard | Tiered pricing |

### Dashboard Design Principles

1. **Most important number first** — If someone has 5 seconds, what should they see?
2. **Trend over snapshot** — A single number is meaningless without direction
3. **Context always** — "12 critical vulns" is noise; "12 critical vulns, up from 3 last month, with 4 in internet-facing apps" is actionable
4. **Drill-down, not scroll-down** — Summary view → click for details
5. **Refresh automatically** — Manual dashboards die within 2 weeks
6. **Alert on threshold breach** — Don't make people watch a dashboard; alert when metrics cross boundaries

---