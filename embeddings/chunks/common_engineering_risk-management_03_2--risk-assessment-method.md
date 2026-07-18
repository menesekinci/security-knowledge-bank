---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "2. Risk Assessment Methodologies"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 3/9
---

## 2. Risk Assessment Methodologies

### 2.1 Qualitative Risk Assessment (High/Medium/Low Matrices)

The most common approach — fast, accessible, but subjective.

**How it works:**
1. Define a 3×3 or 5×5 matrix with likelihood on one axis and impact on the other.
2. Each cell maps to a risk level: Low (green), Medium (yellow), High (red), Critical (dark red).
3. For each risk scenario, the team agrees on a likelihood and impact, then reads the resulting level from the matrix.

**Example 5×5 matrix:**

| Likelihood \ Impact | Insignificant | Minor | Moderate | Major | Catastrophic |
|---|---|---|---|---|---|
| **Almost Certain** | Medium | High | High | Critical | Critical |
| **Likely** | Medium | Medium | High | High | Critical |
| **Possible** | Low | Medium | Medium | High | High |
| **Unlikely** | Low | Low | Medium | Medium | High |
| **Rare** | Low | Low | Low | Medium | Medium |

**Strengths:**
- Quick — can assess a roomful of risks in a single workshop.
- No specialized training needed.
- Communicates well to executives ("It's red").

**Weaknesses:**
- Highly subjective — different assessors give different results.
- Coarse granularity — two "High" risks may have very different actual magnitudes.
- Cannot aggregate risks mathematically (you can't average "High" and "Medium" to get anything meaningful).
- Prone to anchoring bias: the first risk discussed sets the tone for the rest.

**When to use:** Sprint-level decisions, early-stage threat modeling, low-compliance environments.

### 2.2 Quantitative Risk Assessment (FAIR Model)

Quantitative approaches express risk in monetary terms, enabling cost-benefit analysis of controls.

**FAIR (Factor Analysis of Information Risk)** is the most widely adopted framework:

```
Risk = Probable Loss Event Frequency × Probable Loss Magnitude
```

Where:
- **Loss Event Frequency (LEF)** = How often will the loss event occur? (e.g., once per year)
- **Loss Magnitude (LM)** = How much does each occurrence cost? (e.g., $500K)

These break down further into sub-factors:
- **LEF = Threat Event Frequency × Vulnerability (probability of success)**
- **LM = Primary Loss (direct) + Secondary Loss (downstream, e.g., regulatory fines, reputation)**

**Related quantitative metrics:**

| Metric | Formula | Meaning |
|---|---|---|
| **SLE (Single Loss Expectancy)** | Asset Value × Exposure Factor | Cost of one loss event |
| **ARO (Annualized Rate of Occurrence)** | Estimated events per year | How often it's expected to happen |
| **ALE (Annualized Loss Expectancy)** | SLE × ARO | Expected annual cost of the risk |

**Example:**
- Asset: Customer database. Asset Value: $5M. Exposure Factor (if breached): 40% → SLE = $2M
- ARO: Based on industry stats, once every 4 years → ARO = 0.25
- ALE = $2M × 0.25 = **$500K/year**

If a security control costs $200K/year and reduces the ARO to 0.05, the new ALE = $100K/year. ROI of the control = ($500K - $100K) - $200K = **$200K/year saved**.

**Monte Carlo simulation:**
For complex risks, point estimates (single numbers) give false precision. Monte Carlo runs thousands of simulations sampling from probability distributions for each input variable:
- *Input:* "Loss event frequency is a triangular distribution: min=0.1/year, mode=0.25/year, max=0.5/year"
- *Output:* A distribution of probable annual losses, with clear percentiles (P50, P90, P95).

Monte Carlo is powerful for board-level discussions: "There's a 95% probability that unmitigated ransomware will cost us between $2M and $8M this year."

**Strengths:**
- Defensible numbers — auditors and regulators respect quantitative analysis.
- Enables cost-justification of security investments.
- Supports insurance underwriting.

**Weaknesses:**
- Time-intensive — collecting data for dozens of risks is impractical.
- False precision risk — numbers imply accuracy that the inputs don't support.
- Requires analyst skill and historical data.

**When to use:** High-stakes decisions (major control investments, insurance, compliance with SOX/PCI), board reporting, third-party risk management.

---