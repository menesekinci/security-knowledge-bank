---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "4. Trade-off Analysis"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 18/25
---

## 4. Trade-off Analysis

Security never exists in a vacuum. Every security control imposes costs — performance, latency, complexity, usability, operational burden. Engineering leadership requires making explicit, documented trade-offs.

### Common Trade-offs

| Security Concern | Trade-off | Decision Framework |
|---|---|---|
| Encryption at rest | Performance overhead per query | Encrypt sensitive columns only; use application-level encryption for PII, TDE for compliance |
| MFA for all users | Friction in user onboarding | Risk-based MFA: prompt only on new devices or sensitive operations |
| Complete mediation (every access checked) | Increased latency for every request | Cache authorization decisions for short TTL; invalidate on permission change |
| Network micro-segmentation | Operational complexity of managing many security groups | Use service mesh (Istio/Linkerd) for policy-as-code; start with coarse segmentation, refine |
| Input validation on every input | Development velocity | Use framework-level validation (e.g., Zod, Pydantic) to reduce per-endpoint boilerplate |
| FIPS-validated cryptography | Limited algorithm choices, slower implementations | Use FIPS-compatible libraries in user-space; accept performance impact for compliance |

### The Trade-off Canvas

When evaluating a security design decision, use this canvas:

```
┌──────────────────────────────────────────────────┐
│ Decision: ______________________________________ │
├──────────────────────────────────────────────────┤
│ Security Benefit │ Cost │
│ ┌───────────────┐ │ ┌──────────┐ │
│ │ What threats  │ │ │Performance│ │
│ │ are mitigated?│ │ │Complexity │ │
│ │ What is the   │ │ │Usability  │ │
│ │ risk reduction?│ │ │Ops burden │ │
│ └───────────────┘ │ │Cost ($)   │ │
│                    │ └──────────┘ │
├──────────────────────────────────────────────────┤
│ Residual Risk After This Control │
│ ┌──────────────────────────────────────────────┐ │
│ │ What threats are NOT mitigated? │ │
│ │ What is the accepted risk level? │ │
│ └──────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────┤
│ Review Date: ______  Reviewer: ______ │
└──────────────────────────────────────────────────┘
```

### Guiding Principles for Trade-offs

- **Explicit beats implicit** — document the trade-off, don't let it happen by accident
- **Risk-based, not fear-based** — don't apply controls because "everyone says to" — understand the specific threat they address
- **Proportional** — the cost of a control should not exceed the value of the asset it protects
- **Reversible** — prefer controls that can be tightened or loosened without architectural changes

---