---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "8. Tools for Threat Modeling"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 10/13
---

## 8. Tools for Threat Modeling

| Tool | Type | Cost | Best For |
|---|---|---|---|
| **Microsoft Threat Modeling Tool** | Desktop (Windows) | Free | STRIDE-based modeling, DFD creation, automatic threat generation |
| **OWASP Threat Dragon** | Web + Desktop | Free | Cross-platform, STRIDE & LINDDUN, Git-backed model storage |
| **draw.io / diagrams.net** | Web + Desktop | Free | General DFD creation (not threat-specific but flexible) |
| **IriusRisk** | SaaS | Paid | Enterprise threat modeling with risk management workflows |
| **ThreatModeler** | SaaS | Paid | Large organizations, integrates with CI/CD |
| **Toreon Threat Modelling Tool** | SaaS | Paid | Asset-centric modeling, SDLC integration |
| **Structurizr** | DSL-based | Free/Paid | Code-as-diagrams (C4 model), automated DFD generation |
| **Lucidchart** | SaaS | Paid | Collaborative DFDs with threat modeling template library |

### Tool Selection Criteria

- **Team size:** Small teams can use Threat Dragon + draw.io; enterprise needs IriusRisk or ThreatModeler
- **Integration:** Does it plug into Jira, Azure DevOps, GitHub Issues?
- **Granularity:** Do you need per-component threat lists or high-level risk register?
- **Version control:** Can threat models be stored as code (DSL/YAML) and diffed in PR reviews?

---