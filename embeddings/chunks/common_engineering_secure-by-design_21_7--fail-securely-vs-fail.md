---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "7. Fail Securely vs Fail Open"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 21/25
---

## 7. Fail Securely vs Fail Open

Fail-securely (also called fail-closed) is the practice of denying access when a security control fails or encounters an unexpected condition. Fail-open is the opposite — granting access when the control cannot make a decision.

### Decision Matrix

| System Type | Fail Securely (Closed) | Fail Open | Rationale |
|---|---|---|---|
| Firewall | ✅ Block all | ❌ Allow all | Blocked traffic is safe; allowed traffic may be malicious |
| Authentication service | ✅ Reject login | ❌ Allow login | Better to have legitimate users retry than let attackers in |
| Rate limiter | ✅ Block request | ❌ Allow request | A blocked request is annoying; an unblocked attack is dangerous |
| CDN (public assets) | ❌ Block all | ✅ Allow all | Public assets are already public; blocking them hurts UX |
| Circuit breaker | ❌ Block request | ✅ Let request through | Circuit breaker protects the system, not the user; failing open prevents cascading failure |
| Health endpoint | ✅ Return unhealthy | ❌ Return healthy | Better to trigger a re-deploy than serve traffic from a misbehaving instance |

### Implementation Rule

**When in doubt, fail closed.**

If you choose to fail open, three conditions must be met:
1. **Explicit documentation** in an ADR explaining why (e.g., "this CDN serves public assets; there is no confidentiality concern")
2. **Monitoring alert** that fires when the control is in fail-open mode (so humans know the guard is down)
3. **Time-bound** — a maximum duration for how long the system will tolerate a broken control before shutting down

---