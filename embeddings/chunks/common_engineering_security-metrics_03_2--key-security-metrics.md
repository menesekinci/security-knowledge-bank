---
source: "common/engineering/security-metrics.md"
title: "📊 Security Metrics"
heading: "2. Key Security Metrics"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [building, common, common-vuln, measure, metrics, pitfalls, security]
chunk: 3/8
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