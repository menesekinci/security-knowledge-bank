---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "8. Principle 7: Least Common Mechanism"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 10/14
---

## 8. Principle 7: Least Common Mechanism

**"Minimize the amount of mechanism common to more than one user and depended on by all users."**

### What It Means

Shared resources — operating systems, shared memory, global caches, shared databases, multi-tenant services — are single points of failure and attack. Every sharing mechanism represents a potential covert channel, interference vector, or information leak between users.

### High-Risk Shared Mechanisms

| Mechanism | Risk |
|---|---|
| Shared database tables | One tenant's data leak can expose all tenants |
| Global in-memory cache | Cache key collisions, shared namespace pollution |
| /tmp directory | Information disclosure via predictable filenames |
| Single build pipeline | Poisoned build affects all downstream artifacts |
| Shared CDN origin | Cache poisoning serves malicious content to all users |
| Global feature flags | A misconfigured flag affects every tenant |

### Real-World Engineering Scenario

**Scenario:** Multi-tenant SaaS — all customers share the same application process.

The application uses a global cache to store session data. A cache key collision between Tenant A and Tenant B means Tenant A's authenticated session could be presented to the application as Tenant B. This is a least-common-mechanism violation: the global cache is a shared mechanism that all tenants depend on.

**Fix:** Prefix all cache keys with a tenant-specific namespace. Better yet, use a separate cache instance per tenant for sensitive data, accepting the operational cost for high-security customers.

### Mitigation Tactics

- **Namespace everything** — tenant ID, user ID, or application ID should prefix every shared resource key
- **Rate-limit per tenant** — one tenant's misbehavior should not degrade service for others (noisy neighbor)
- **Isolation boundaries** — use separate processes, containers, VMs, or accounts for different trust levels
- **Side-channel awareness** — shared CPU caches, timing channels, and memory bandwidth can leak information across tenants even in "isolated" environments

---