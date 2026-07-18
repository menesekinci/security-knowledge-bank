---
source: "common/engineering/incident-response-deep.md"
title: "🔴 Incident Response — Deep Engineering Guide"
heading: "3. Communication"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, communication, detection, philosophy, practical, signals]
chunk: 4/22
---

## 3. Communication

### Internal Communication

During an incident, communication must be precise, timely, and documented.

**Communication roles:**

| Role | Responsibility | Who |
|------|---------------|-----|
| **Incident Commander (IC)** | Single decision-maker, coordinates all actions | Security lead or SRE on call |
| **Scribe** | Documents timeline, decisions, and actions | Rotating engineering role |
| **Subject Matter Experts (SMEs)** | Technical investigation and remediation | Engineers from affected teams |
| **Liaison** | Communication bridge to execs, legal, PR | Engineering manager or PM |

**Incident communication channels:**
- **Dedicated Slack channel** — `#incident-<id>` — all technical discussion
- **Bridge call / Zoom** — For IC, SMEs, scribe (real-time coordination)
- **Status page** — Customer-facing updates (for external incidents)

**Communication cadence:**
```
ONGOING INCIDENT ─── STATUS UPDATES ─────────────────────────────
│
├── Every 30 min (Critical) / 60 min (High)
│   └── IC brief to stakeholders via Slack thread or email
│
├── Every update includes:
│   ├── Current status (Active / Contained / Recovering)
│   ├── What we know (facts only, no speculation)
│   ├── What we're doing (current containment/remediation)
│   ├── What we need (cross-team help, approvals)
│   └── ETA for next update
│
└── Keep the scribe timeline updated after every action
```

### External Communication

**When to notify externally:**
- Customer data has been accessed or exfiltrated
- Service is degraded or unavailable due to security incident
- Regulatory requirement triggered (GDPR 72h, CCPA, PCI-DSS)
- Attacker has publicly claimed responsibility

**External notification tiers:**

| Tier | Audience | Content | Channel |
|------|----------|---------|---------|
| **T1** | All customers | Service degradation only | Status page |
| **T2** | Affected customers only | Data incident, remediation steps | Email + direct notification |
| **T3** | Regulatory bodies | Breach notification per regulation | Formal breach report |
| **T4** | Public / press | Major breach with public impact | Press release, blog post |

### Regulatory Disclosure Requirements

| Regulation | Notification Trigger | Timeline | Method |
|-----------|---------------------|----------|--------|
| **GDPR** | Personal data breach | Within 72 hours of awareness | Email + supervisory authority |
| **CCPA/CPRA** | Unauthorized access to PII | No specific timeline, "without unreasonable delay" | Email, mail, or account notification |
| **PCI-DSS** | Account data compromise (CDE) | ASAP, within 24 hours for acquiring banks | Formal incident report to acquirer |
| **HIPAA** | Breach of unsecured PHI | Within 60 days of discovery | Email or mail + HHS notification |
| **SOC 2** | Security incident affecting controls | Per contractual SLA (typically 48–72h) | Incident report to customers |

---