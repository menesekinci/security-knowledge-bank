---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "3. Principle 2: Least Privilege"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 5/14
---

## 3. Principle 2: Least Privilege

**"Every program and every user should operate using the smallest set of privileges necessary to complete the job."**

### What It Means

Least privilege applies at every level: OS processes, database roles, IAM policies, API tokens, container permissions, and human access. The principle is violated far more often than it is honored, usually in the name of "convenience" or "getting it shipped."

### Engineering Applications

| Domain | Least-Privilege Practice | Common Violation |
|---|---|---|
| IAM Roles | Scoped policies per service | Single "admin" role for everything |
| Database | Read-only replicas for queries, specific table grants | One connection string per environment |
| Containers | Drop all capabilities, add only needed ones | Running as root with `--privileged` |
| CI/CD | Token per environment, branch-scoped | Single deploy key for all environments |
| Service Accounts | Separate accounts per service, rotation | Shared static keys |
| Filesystem | Read-only root, temp dirs with no-exec | World-writable directories |

### Real-World Engineering Scenario

**Scenario:** A CI/CD pipeline building and deploying a web service.

- The **build step** only needs access to the source repository (read) and an artifact registry (write).
- The **test step** needs no production credentials at all — it runs against ephemeral test databases.
- The **deploy step** needs a short-lived token scoped to exactly one service in one environment.

An attacker who compromises the build step (e.g., via a poisoned dependency) cannot use it to tamper with production — there are no production credentials available in that context.

### Implementation Patterns

- **Just-In-Time (JIT) Access:** Request temporary elevation for specific operations with automatic expiry
- **Attribute-Based Access Control (ABAC):** Permissions based on resource tags, time, location, and device posture
- **Privilege Separation:** Split a monolith binary into distinct processes, each running with different user IDs

---