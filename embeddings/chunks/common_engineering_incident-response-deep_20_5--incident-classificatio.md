---
source: "common/engineering/incident-response-deep.md"
title: "🔴 Incident Response — Deep Engineering Guide"
heading: "5. Incident Classification"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, communication, detection, philosophy, practical, signals]
chunk: 20/22
---

## 5. Incident Classification

### SEV-1 Through SEV-4 Definitions

| Severity | Label | Description | Response Time | SLA | Examples |
|----------|-------|-------------|---------------|-----|----------|
| **SEV-1** | 🔴 Critical | Active data breach, RCE in production, complete service loss due to security event | < 15 min | 24/7 | Attacker exfiltrating database, ransomware encrypting prod servers |
| **SEV-2** | 🟠 High | Confirmed vulnerability with exploit potential, partial service compromise, credentials leaked | < 60 min | Business hours + on-call escalation | PII exposed but not exfiltrated, AWS key committed to public repo |
| **SEV-3** | 🟡 Medium | Unconfirmed potential incident, non-critical misconfiguration, dependency with CVE | < 4 hours | Business hours | Suspicious login pattern, S3 bucket possibly public, Log4j in dependency tree |
| **SEV-4** | 🟢 Low | Low-risk finding, policy violation with no evidence of exploitation | < 1 week | Next business day | Unused IAM key, missing audit log, TLS version too old |

### Escalation Paths

```
SEV-1 ──────────────────────────────────────────────────────────
│  IC: Head of Security or CISO
│  SMEs: All engineering leads, on-call SRE
│  Exec: CTO / CEO notified
│  Legal: GC notified for data incidents
│  Communication: Every 30-min status to exec team
│
├── SEV-2 ─────────────────────────────────────────────────────
│   IC: Security lead or senior SRE
│   SMEs: Affected team's lead engineer
│   Exec: Engineering manager notified
│   Communication: Hourly status update
│
├── SEV-3 ─────────────────────────────────────────────────────
│   IC: Security engineer on call
│   SMEs: On-call developer for the affected service
│   Communication: Daily update during resolution
│
└── SEV-4 ─────────────────────────────────────────────────────
    IC: Security engineer
    Action: Logged as ticket, assigned to sprint
    Communication: Not required
```

### Escalation Rules

- **Auto-escalate** if active containment not completed within SLA for the current SEV level
- **Any responder can escalate** — no permission needed to bump SEV level
- **De-escalation** requires IC + next-level manager approval
- **Time-based escalation:** If SEV-1 not contained in 1 hour, auto-escalate to CISO/CEO

---