---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "1. What 'Secure by Design' Means"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 3/25
---

## 1. What "Secure by Design" Means

Secure by Design (SbD) is the practice of integrating security considerations into the architecture and design of a system from the very beginning — not adding security controls as an afterthought when vulnerabilities are discovered. It is the difference between:

| Bolt-on Security (Afterthought) | Secure by Design (Built-in) |
|---|---|
| Add authentication middleware after penetration test finds no auth | Authentication is part of the component model from sprint 1 |
| Run a SAST scan and fix findings | Architecture itself prevents entire classes of vulnerabilities (e.g., no SQL injection because data access is fully parameterized by the framework) |
| "We'll encrypt data later" | Data classification and encryption strategy are part of the design doc |
| Security reviewed as a separate gate | Security reviewed as part of every architecture decision |
| Risk accepted because "we can't change the design now" | Design explicitly accounts for risk trade-offs |

### The SbD Mindset

1. **Threat modeling is a design tool**, not a security deliverable.
2. **Every design decision is a security decision** — even choosing a serialization format, a caching strategy, or a deployment model.
3. **Security requirements are functional requirements** — if confidentiality is a requirement, it is as real as "the user can save a document."
4. **Default deny over default allow** — every component, every endpoint, every permission starts locked down.

---