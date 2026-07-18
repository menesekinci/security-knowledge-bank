---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "9. Integrating Threat Modeling into Agile"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 11/13
---

## 9. Integrating Threat Modeling into Agile

Threat modeling is often seen as a "waterfall" activity, but it works in agile too. The key is **right-sizing** — not every story needs a full PASTA exercise.

### Sprint-Level (Lightweight Threat Modeling)

**When:** Every sprint, for stories that introduce new data flows or new trust boundaries.
**Duration:** 15–30 minutes during sprint planning or design review.
**Format:** "Three questions" — (1) What new data flows are we adding? (2) What trust boundaries are we crossing? (3) What could go wrong with each?
**Output:** 2–3 threats documented in the story's acceptance criteria.

### Release-Level (Standard Threat Modeling)

**When:** Before every major release or feature launch.
**Duration:** 1–2 hours.
**Format:** Full STRIDE-per-element session with a DFD.
**Output:** Threat table, mitigation list, test cases added to release regression suite.

### Quarterly (Deep Dive)

**When:** Once per quarter for critical services.
**Duration:** 1–2 days per system.
**Format:** PASTA stages 1–7 or full STRIDE with attack tree modeling.
**Output:** Risk register update, mitigation roadmap, executive summary.

### Making It Stick

- **Dedicated security champion** in every team — trains on threat modeling, facilitates sessions
- **Threat model in pull requests** — every PR that changes a DFD element must include or update the threat model
- **Threat model as code** — store DFDs and threat tables alongside the source code in `.threat-models/` directory
- **Gamify it** — "Threat of the Sprint" award for the best threat identified

---