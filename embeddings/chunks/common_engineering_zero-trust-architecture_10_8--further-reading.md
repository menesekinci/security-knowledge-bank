---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "8. Further Reading"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 10/10
---

## 8. Further Reading

### Standards and Frameworks

- **NIST SP 800-207** — *Zero Trust Architecture* — the definitive US government standard defining Zero Trust principles, components, and deployment models
- **CISA Zero Trust Maturity Model** — practical maturity model across the five pillars with specific capabilities at each level (Traditional → Advanced → Optimal)
- **Forrester Zero Trust eXtended (ZTX)** — the original Zero Trust framework that introduced the "never trust, always verify" concept

### Implementation Guides

- **Google BeyondCorp Papers** (6 papers, 2014–2021) — detailed architectural description of Google's Zero Trust implementation
  - *BeyondCorp: A New Approach to Enterprise Security* (2014) — the original paper
  - *BeyondCorp: The Access Proxy* (2021) — deep dive on the proxy architecture
- **Cloudflare Zero Trust Documentation** — practical implementation guides with a SaaS model
- **Tailscale "How It Works"** — explanation of identity-based networking without VPN complexity

### Books

- **"Zero Trust Networks"** by Razi Rais, Christina Morillo, Evan Gilman, and Doug Barth — practical implementation guide
- **"The Zero Trust Framework"** by Ravinder Das — focuses on implementation strategy for enterprises
- **"Designing and Implementing a Zero Trust Architecture"** by Vinay Laxmi J — NIST-focused approach for regulated industries

---

> **Key Takeaway:** Zero Trust is not a technology you buy — it is an operating model you adopt. Start with identity (SSO + MFA), add device verification, segment your network, and build application-level authorization. Do it incrementally, measure progress against the CISA maturity model, and remember: Zero Trust is a journey, not a destination. Every step you take from implicit trust toward explicit, continuous verification makes your system harder to compromise.