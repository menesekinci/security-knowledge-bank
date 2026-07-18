---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "1. What Is Threat Modeling?"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 3/13
---

## 1. What Is Threat Modeling?

Threat modeling is a structured approach to identifying what could go wrong in a system from a security perspective — *before* it ships. It is not a penetration test, a code review, or a compliance checkbox. It is a design-time activity that answers four questions:

1. **What are we building?** (System context, trust boundaries, data flows)
2. **What can go wrong?** (Threats — the "attack" side of the equation)
3. **What are we doing about it?** (Mitigations — the "defense" side)
4. **Did we do a good job?** (Validation — tests, reviews, residual risk acceptance)

### Why Threat Model?

| Reason | Explanation |
|---|---|
| **Shift left** | Finding a design flaw in production costs 100x more than finding it during design |
| **Shared mental model** | Developers, architects, security, and product align on what the system does and where risk lives |
| **Defensible decisions** | Documented threat models justify why a control exists (or why a risk was accepted) |
| **Test case generation** | Threats translate directly to security test scenarios and abuse cases |
| **Compliance evidence** | Regulators and auditors increasingly expect evidence of threat modeling |

---