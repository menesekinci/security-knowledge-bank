---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "5. Choosing a Methodology"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 7/13
---

## 5. Choosing a Methodology

| Factor | STRIDE | PASTA | LINDDUN |
|---|---|---|---|
| **Focus** | Security threats | Risk-based analysis | Privacy threats |
| **Depth** | Medium | High | Medium-High |
| **Time required** | 1–3 hours per component | 2–5 days for full process | 1–3 hours per data flow |
| **Who leads** | Engineer + security champion | Dedicated security architect | Privacy engineer / DPO |
| **Best for** | Web apps, APIs, microservices | Complex, critical, regulated systems | Systems handling PII |
| **Deliverable** | Threat list with mitigations | Risk register + attack trees | Privacy threat model + PIA |
| **Learning curve** | Low | High | Medium |

### Hybrid Approach

Many mature teams use **STRIDE for sprint-level threat models** (fast, focused) and **PASTA for quarterly deep dives** on critical systems. LINDDUN runs alongside whichever methodology is chosen whenever PII flows are involved.

---