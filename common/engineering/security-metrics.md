# 📊 Security Metrics

> **Category:** Common / Engineering
> **Last Updated:** July 2026
> **Description:** Measuring security engineering effectiveness — key metrics, audience-specific dashboards, and common pitfalls. Data-driven security management for engineering teams.

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

## 2. Key Security Metrics

### MTTD — Mean Time to Detect

*How long between incident start and the first alert/notification.*

```
MTTD = Σ(Detection Time - Incident Start Time) / Number of Incidents
```

| Benchmark | Value |
|-----------|-------|
| World-class | < 1 minute |
| Good | < 10 minutes |
| Average | 1–4 hours |
| Needs improvement | > 24 hours |

**How to improve MTTD:**
- Shift from log-based detection to real-time stream processing
- Implement automated alerting on key behavioral signals
- Reduce alert noise (high false positive rate causes alert fatigue and missed detections)
- Add anomaly detection layers (user behavior, network traffic, API patterns)

### MTTR — Mean Time to Respond / Remediate

*How long between detection and containment (MTTR-Contain) or full eradication (MTTR-Resolve).*

```
MTTR-Contain = Σ(Containment Time - Detection Time) / Number of Incidents
MTTR-Resolve = Σ(Resolution Time - Detection Time) / Number of Incidents
```

| Benchmark | MTTR-Contain | MTTR-Resolve |
|-----------|-------------|--------------|
| World-class | < 15 min | < 1 hour |
| Good | < 1 hour | < 4 hours |
| Average | 2–4 hours | 8–24 hours |
| Needs improvement | > 8 hours | > 72 hours |

**What drives MTTR:**
- Runbook quality and test frequency
- Tool integration (how many clicks to contain a compromised instance?)
- Access to logs and forensics data
- Incident commander training and authority
- Automation of repetitive containment actions

### Vulnerability Density

*Number of vulnerabilities per thousand lines of code (KLOC).*

```
Vulnerability Density = Total Vulnerabilities Found / Total KLOC
```

| Benchmark | Value |
|-----------|-------|
| Excellent | < 0.1 / KLOC |
| Good | 0.1 – 0.5 / KLOC |
| Average | 0.5 – 1.0 / KLOC |
| Needs review | > 1.0 / KLOC |

**Important caveats:**
- Only meaningful when comparing similar codebases (language, complexity, age)
- Better as a trend metric (improving or worsening?) than an absolute number
- Critical vulns matter more than total count — consider severity-weighted density

### Mean Time to Patch (Critical Vulnerabilities)

*How long between a critical CVE publication (or internal discovery) and production patch deployment.*

```
MTTP = Σ(Patched Time - CVE Publication Time) / Number of Critical CVEs
```

| Risk | Time Window |
|------|-------------|
| 🔴 Critical with active exploitation | < 24 hours |
| 🟠 Critical without known exploitation | < 7 days |
| 🟡 High severity | < 30 days |
| 🟢 Medium/Low | < 90 days or per policy |

**Segmentation is key:**
- Track MTTP separately for internet-facing vs. internal systems
- Track MTTP separately for OS-level vs. application-level vs. dependency patching
- Track MTTP by risk: is the CVE being actively exploited? Is it in a critical system?

### Security Debt

*Cumulative unfixed vulnerabilities over time — analogous to technical debt.*

```
Security Debt = Σ(Severity × Weighted Time Unfixed) per Vulnerability
```

Simple version: count of unpatched critical + high vulnerabilities older than SLA.

**Security debt trend:**

```
Date       | Critical | High | Security Debt Score
2026-01-01 |    3     |  12  |  3×30 + 12×14 = 258
2026-02-01 |    1     |   8  |  1×30 +  8×14 = 142
2026-03-01 |    0     |   4  |  0×30 +  4×14 =  56
```

**Watch out for:**
- Security debt that plateaus (new vulns arriving as fast as they're fixed)
- "Zombie vulns" — findings that keep getting postponed in every sprint
- Debt in critical path services vs. non-critical — weight by business impact

### Coverage Metrics

*How well your security tooling covers your assets.*

| Coverage Metric | Target | How to Measure |
|-----------------|--------|----------------|
| **SAST scan coverage** | 100% of repos | % of repos with SAST run in CI |
| **DAST scan coverage** | 100% of web apps | % of production endpoints DAST-scanned monthly |
| **SCA coverage** | 100% of repos | % of repos with dependency scanning |
| **Image scan coverage** | 100% of container images | % of images scanned before deploy |
| **Secret scan coverage** | 100% of repos | % of repos with secret scanning (git history + CI) |
| **IaC scan coverage** | 100% of IaC repos | % of Terraform/CloudFormation repos scanned |
| **Log coverage** | 100% of critical systems | % of servers/services shipping logs to SIEM |

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

## 6. Metrics-Driven Improvement Cycle

```
┌─────────────────────────────────────────────────────────────┐
│                  METRICS DRIVEN IMPROVEMENT                   │
│                                                               │
│  1. MEASURE ──→ Collect baseline data (4-8 weeks)            │
│       │                                                       │
│  2. ANALYZE ──→ Find the biggest gap (MTTD? MTTP? Coverage?) │
│       │                                                       │
│  3. PRIORITIZE ──→ Choose ONE metric to improve              │
│       │                                                       │
│  4. INVEST ──→ Allocate tooling, process, or people          │
│       │                                                       │
│  5. MEASURE AGAIN ──→ Did it move? (Wait 2 cycles)           │
│       │                                                       │
│  6. CELEBRATE OR PIVOT ──→ Success? Pick next. No? Try new   │
│       │                                                       │
│  REPEAT ──────────────────────────────────────────────────┘  │
```

**One-metric-at-a-time principle:** Improving 5 metrics by 5% each is harder and less visible than improving 1 metric by 50%. Focus.

---

## 7. References

- [OWASP Security Metrics](https://owasp.org/www-project-security-metrics/)
- [NIST Security Metrics Framework](https://csrc.nist.gov/projects/security-metrics)
- [Security Metrics: A Beginner's Guide — Caroline Wong](https://www.oreilly.com/library/view/security-metrics-a/9780071744005/)
- [SANS Security Metrics Consensus Project](https://www.sans.org/security-metrics/)
- [Google's Guide to Security Metrics](https://sre.google/sre-book/security-metrics/)
- [CIS Security Metrics](https://www.cisecurity.org/insights/blog/security-metrics-that-matter)
- [VERIS Framework (Vocabulary for Event Recording and Incident Sharing)](https://github.com/vz-risk/veris)
- [ISO 27004 — Information security management monitoring and measurement](https://www.iso.org/standard/80287.html)
- [Building Security In Maturity Model (BSIMM)](https://www.bsimm.com/)
- [FAIR Model — Factor Analysis of Information Risk](https://www.fairinstitute.org/)
