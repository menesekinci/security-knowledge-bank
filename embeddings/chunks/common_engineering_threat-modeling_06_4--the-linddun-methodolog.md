---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "4. The LINDDUN Methodology"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 6/13
---

## 4. The LINDDUN Methodology

LINDDUN (derived from **L**inkability, **I**dentifiability, **N**on-repudiation, **D**etectability, **D**isclosure of information, **U**nawareness, **N**on-compliance) is a privacy-focused threat modeling methodology from KU Leuven.

### LINDDUN Categories

| Category | Meaning | Privacy Principle |
|---|---|---|
| **L**inkability | Can two data points be linked to the same individual? | Unlinkability |
| **I**dentifiability | Can an individual be identified from the data? | Anonymity & Pseudonymity |
| **N**on-repudiation | Can a user be held accountable (privacy concern)? | Plausible deniability |
| **D**etectability | Can an attacker determine if data about a person exists? | Undetectability & Unobservability |
| **D**isclosure of Information | Is personal data exposed to unauthorized parties? | Confidentiality |
| **U**nawareness | Is the user informed and in control? | User awareness & consent |
| **N**on-compliance | Does the system violate privacy regulations? | Compliance |

### LINDDUN Process

1. **Model the system** — create DFDs annotated with personal data flows (which flows carry PII?).
2. **Map privacy threats** — for each DFD element, ask "Which LINDDUN threats apply?"
3. **Identify mitigation strategies** — data minimization, anonymization, aggregation, consent interfaces, deletion capabilities.
4. **Prioritize** — focus on threats with legal/compliance impact first.
5. **Implement privacy controls** — pet names, differential privacy, data retention limits, right-to-deletion workflows.
6. **Validate** — privacy impact assessment (PIA), data protection officer (DPO) review.

### When to Use LINDDUN

- **GDPR/HIPAA/PIPEDA compliance** — any system processing personal data
- **Consumer-facing products** — apps, IoT devices, platforms with user accounts
- **Data analytics pipelines** — where aggregate data could be de-anonymized
- **Biometric or health-data systems** — highest privacy risk

---