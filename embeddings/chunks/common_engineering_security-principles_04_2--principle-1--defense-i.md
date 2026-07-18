---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "2. Principle 1: Defense in Depth"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 4/14
---

## 2. Principle 1: Defense in Depth

**"No single layer of defense should be relied upon. Multiple, overlapping controls ensure that if one fails, another catches the failure."**

### What It Means

Defense in Depth (DiD) rejects the idea of a "magic shield" — a single gate that, if passed, means the system is safe. Instead, multiple independent controls are layered so that an attacker must defeat several different kinds of protection to succeed.

### Layering Model

```
┌─────────────────────────────────────────────┐
│  Policy & Governance                        │
├─────────────────────────────────────────────┤
│  Physical Security                          │
├─────────────────────────────────────────────┤
│  Network Security (firewalls, segmentation) │
├─────────────────────────────────────────────┤
│  Host Security (hardening, patching)        │
├─────────────────────────────────────────────┤
│  Application Security (auth, validation)    │
├─────────────────────────────────────────────┤
│  Data Security (encryption, masking)        │
└─────────────────────────────────────────────┘
```

### Real-World Engineering Scenario

**Scenario:** A payment processing microservice.

| Layer | Control |
|---|---|
| Network | Service mesh mTLS, network policy restricting ingress to only the order service |
| Application | JWT validation, rate limiting, input sanitization on every endpoint |
| Host | Container runs as non-root, read-only root filesystem |
| Data | Database connection uses separate credentials scoped to minimum tables |
| Audit | Every payment event logged to an immutable audit trail |

If the JWT is compromised (e.g., leaked signing key), the attacker still faces mTLS, database credential scoping, and audit logging. No single breach cascades into total compromise.

### Common Pitfalls

- **Flat networks** — once inside the perimeter, everything is reachable
- **Single-sign-on as single point of failure** — a compromised IdP should not grant access to everything
- **Encryption-only thinking** — encrypting data in transit helps, but does nothing if the application itself is vulnerable
- **Alert fatigue** — too many controls with no operational capacity to respond to alerts

---