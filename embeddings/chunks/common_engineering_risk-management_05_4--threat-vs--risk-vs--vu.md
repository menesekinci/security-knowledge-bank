---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "4. Threat vs. Risk vs. Vulnerability — The Difference Matters"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 5/9
---

## 4. Threat vs. Risk vs. Vulnerability — The Difference Matters

These three terms are often used interchangeably, but the distinctions drive different actions:

| Term | Definition | Example | Action |
|---|---|---|---|
| **Threat** | Something that can cause harm | A ransomware group targeting your industry | Intelligence gathering, threat modeling |
| **Vulnerability** | A weakness that can be exploited | Unpatched Log4j version in a public-facing app | Patching, WAF rules, mitigation |
| **Risk** | The *potential* for loss when a threat exploits a vulnerability | Ransomware encrypts the unpatched server, causing $500K in downtime | Risk assessment, control decisions |

**Simple framing:**
- *Threat* = the arrow (motivated, capable attacker)
- *Vulnerability* = the hole in your armor (missing patch, misconfiguration)
- *Risk* = the likelihood that the arrow hits the hole and the damage it causes

**Why it matters operationally:**
- If you have a high risk, ask: is it because the threat is active, or because the vulnerability is severe? The mitigation strategy differs:
  - High threat: improve detection and response (you can't eliminate the threat).
  - High vulnerability: fix the weakness (patching, hardening, redesign).
- If your risk register is full of unlikely threat scenarios, you may be overestimating risk. If it's full of unpatched vulns, you're underestimating vulnerability likelihood.

---