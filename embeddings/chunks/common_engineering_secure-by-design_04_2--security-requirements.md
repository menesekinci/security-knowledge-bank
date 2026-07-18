---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "2. Security Requirements Engineering"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 4/25
---

## 2. Security Requirements Engineering

Security requirements cannot be an afterthought uncovered by a scan. They must be derived from business requirements, regulatory obligations, and threat modeling — *then* translated into engineering specifications.

### Deriving Security Requirements

```
Business Requirements
        │
        ▼
    Regulatory Obligations ──→ Security Requirements ←── Threat Modeling
        │                                       │
        ▼                                       ▼
    Compliance Controls                    Engineering Specifications
```

### Process: From Business to Security Requirements

**Step 1: Identify business assets and their value.**
- What data do we handle? (PII, financial, authentication secrets, intellectual property)
- What happens if this data is exposed, modified, or unavailable?
- What is the maximum acceptable downtime for each function?

**Step 2: Identify regulatory and contractual obligations.**
- GDPR, CCPA, HIPAA, PCI-DSS, SOC 2, FedRAMP
- Customer contracts with specific security requirements
- Industry standards (NIST 800-53, ISO 27001, CIS Benchmarks)

**Step 3: Identify threats (from threat modeling).**
- What are the top STRIDE threats for each component?
- What are the realistic attack scenarios?

**Step 4: Derive security requirements.**
- Each threat → one or more security requirements
- Each regulatory clause → one or more security requirements
- Each business asset → classification and handling requirements

**Step 5: Write testable security requirements.**

| Bad Requirement | Good (Testable) Requirement |
|---|---|
| "The system must be secure" | "All HTTP responses must include `Content-Security-Policy` header with `script-src 'self'`" |
| "Passwords must be stored safely" | "Passwords must be hashed with bcrypt, cost factor ≥ 10, before storage" |
| "Access control must be enforced" | "Every API endpoint must validate the caller's JWT and check resource ownership before returning data" |
| "Data must be encrypted" | "All PII fields in the database must be encrypted at rest using AES-256-GCM with keys managed by AWS KMS" |

### Common Security Requirement Categories

| Category | Example Requirements |
|---|---|
| **Authentication** | MFA for admin access, rate-limited login, password complexity (NIST 800-63B) |
| **Authorization** | RBAC for all resources, ownership validation on every operation |
| **Audit** | Immutable logs for all auth decisions and data modifications |
| **Confidentiality** | Encryption at rest and in transit, data classification labels |
| **Integrity** | Code signing, subresource integrity, database constraint validation |
| **Availability** | Rate limiting, resource quotas, redundancy, DoS protection |
| **Privacy** | Data minimization, retention limits, deletion workflows, consent management |

---