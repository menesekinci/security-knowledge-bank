---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "1. What Is Security as Code"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 2/8
---

## 1. What Is Security as Code

Security as Code (SaC) is the practice of expressing security policies, compliance requirements, and infrastructure security controls as machine-readable, version-controlled, and automatically enforced code — the same discipline developers apply to application code.

### The Core Shift

| Traditional Security                 | Security as Code                         |
|--------------------------------------|------------------------------------------|
| Manual compliance checklists         | Automated, gated policy enforcement      |
| PDF policy documents                 | Version-controlled Rego/Cedar policies   |
| Point-in-time audits                 | Continuous, every-deploy compliance      |
| Human-driven reviews                 | CI/CD-integrated policy evaluation       |
| Detective controls only              | Preventive + Detective guardrails        |

### Three Pillars of Security as Code

1. **Policy as Code** — Encode what is allowed or denied (OPA/Rego, Cedar, Sentinel)
2. **Compliance as Code** — Codify regulatory and internal compliance controls (InSpec, cnspec, CloudQuery)
3. **Guardrails as Code** — Define preventive and detective boundaries (AWS SCPs, Azure Policy, Kubernetes Admission Controllers)

### Preventive vs. Detective Controls

```
┌─────────────────────────────────────────────────────────────┐
│                   SECURITY CONTROLS                           │
├─────────────────────────┬───────────────────────────────────┤
│   PREVENTIVE            │   DETECTIVE                        │
│                         │                                   │
│  • Blocks before        │  • Alerts after                   │
│    the fact             │    the fact                        │
│  • Rejects violating    │  • Reports violations             │
│    resources/deploys    │    for triage                      │
│  • Examples:            │  • Examples:                       │
│    – OPA/Gatekeeper     │    – Security Hub                 │
│    – SCPs               │    – GuardDuty                    │
│    – Terraform checks   │    – CloudTrail/Alerts            │
│    – Pre-commit hooks   │    – SIEM queries                 │
│    – Admission Webhooks │    – Drift detection              │
└─────────────────────────┴───────────────────────────────────┘
```

---