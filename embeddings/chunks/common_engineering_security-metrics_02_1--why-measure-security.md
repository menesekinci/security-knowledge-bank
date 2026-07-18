---
source: "common/engineering/security-metrics.md"
title: "📊 Security Metrics"
heading: "1. Why Measure Security"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [building, common, common-vuln, measure, metrics, pitfalls, security]
chunk: 2/8
---

## 1. Why Measure Security

Security is often viewed as a cost center. Metrics are the language that translates security activity into business value — they justify budget, demonstrate progress, and focus effort on what matters.

### What Gets Measured Gets Managed

Without metrics, security decisions are driven by:
- **The loudest voice** — whoever complains most gets resources
- **The latest headline** — jumping from one CVE panic to the next
- **Confirmation bias** — measuring what we're already good at

With metrics, decisions are driven by:
- **Trend direction** — are we getting better or worse?
- **Comparative analysis** — how do we compare to peers or benchmarks?
- **Resource allocation** — where does the next dollar of security spend have the most impact?

### Avoiding Vanity Metrics

A vanity metric looks impressive but doesn't drive action or reflect real security posture.

| Vanity Metric | Why It's Vanity | Better Alternative |
|---------------|-----------------|-------------------|
| Number of vulns found this month | Doesn't tell you if you're fixing them | Mean time to remediate (MTTR) |
| Total security tests run | More tests ≠ better security | Test pass rate for security-critical tests |
| Security tool coverage % | Having a tool doesn't mean using it effectively | Coverage of security events actually reviewed |
| Number of blocked attacks | Blocked by design is normal; blocked ≠ secure | False negative rate (attacks that got through) |
| Compliance score (point-in-time) | Snapshot can be gamed | Trend over time + real drift detection |

**The litmus test for any metric:** "If this number goes up/down by 10%, what specific action should I take?" If you can't answer, it's a vanity metric.

---