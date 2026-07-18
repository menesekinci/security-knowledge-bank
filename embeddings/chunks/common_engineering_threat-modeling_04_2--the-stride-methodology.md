---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "2. The STRIDE Methodology"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 4/13
---

## 2. The STRIDE Methodology

STRIDE was developed by Microsoft in the late 1990s as part of their Security Development Lifecycle (SDL). It classifies threats into six categories, one per letter of the acronym.

### STRIDE Categories

| Category | Definition | Violates | Example |
|---|---|---|---|
| **S**poofing | Pretending to be someone or something else | Authentication | Attacker forges a JWT claiming to be `admin` |
| **T**ampering | Modifying data or code without authorization | Integrity | Attacker modifies a database row via SQL injection |
| **R**epudiation | Denying having performed an action | Non-repudiation | Operator deletes logs after performing unauthorized action |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Confidentiality | Stack trace reveals database connection string |
| **D**enial of Service | Disrupting service availability | Availability | Attacker floods login endpoint with slow requests |
| **E**levation of Privilege | Gaining unauthorized access or permissions | Authorization | Regular user exploits a path traversal to access admin API |

### STRIDE Per Element

The most effective way to apply STRIDE is to examine each element of a Data Flow Diagram (see §6) against each category:

| DFD Element | S | T | R | I | D | E | Focus |
|---|---|---|---|---|---|---|---|
| **External Entity** | ✓ | | ✓ | | | | Who is this? Can they lie about who they are? |
| **Process** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Everything — processes are ground zero for threats |
| **Data Store** | | ✓ | ✓ | ✓ | ✓ | | Is data protected at rest? Can it be tampered? |
| **Data Flow** | | ✓ | | ✓ | | | Is data in transit encrypted? Can it be intercepted? |

### How to Run a STRIDE Session

1. **Draw the DFD** (see §6) with trust boundaries marked.
2. **Walk each element** and ask: "What STRIDE threats apply here?"
3. **Document each threat** in a table:
   ```
   | ID | Element | STRIDE | Threat Description | Mitigation | Severity | Status |
   ```
4. **Prioritize** using DREAD or CVSS scoring (see §2.1 below).
5. **Assign mitigations** — for each threat, decide: mitigate (implement control), transfer (insurance/SLA), eliminate (redesign), or accept (document risk).

#### Prioritization: DREAD (Optional)

Microsoft also defined DREAD for ranking threats:

| Letter | Meaning | Scale (1–10) |
|---|---|---|
| **D**amage Potential | How severe is the damage? | 1=minor info leak, 10=complete compromise |
| **R**eproducibility | How easily can the attack be reproduced? | 1=extremely hard, 10=easy script |
| **E**xploitability | How much skill/access is needed? | 1=requires expert+phys access, 10=unauthenticated |
| **A**ffected Users | How many users are impacted? | 1=very few, 10=all |
| **D**iscoverability | How easy is it to find the vulnerability? | 1=very hard, 10=publicly known |

**Total = (D + R + E + A + D) / 5**

> **Note:** DREAD is subjective. Many teams now prefer CVSS v3+ scoring for its wider industry calibration.

### STRIDE Variants

- **STRIDE-per-Element** — process each DFD element independently (most common)
- **STRIDE-per-Interaction** — examine each data flow between elements (better for complex microservice architectures)
- **STRIDE-LM** — STRIDE with "Lateral Movement" added for network-centric threat models

---