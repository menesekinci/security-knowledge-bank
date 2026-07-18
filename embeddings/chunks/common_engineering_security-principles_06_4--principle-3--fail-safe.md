---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "4. Principle 3: Fail Safe"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 6/14
---

## 4. Principle 3: Fail Safe

**"When a system fails, it should fail in a state that denies access rather than grants it."**

### What It Means

Also called "fail closed" or "fail secure." The default response to an error, exception, or unexpected condition should be to deny the operation. The alternative — "fail open" — means that when a security control breaks, access is implicitly granted.

### Fail-Closed vs Fail-Open Examples

| Control | Fail Closed (Secure) | Fail Open (Insecure) |
|---|---|---|
| Firewall rule | Drop all traffic on rule engine crash | Allow all traffic |
| Authentication service | Reject login if IdP unreachable | Let user in |
| Authorization check | Deny access on cache miss | Allow access |
| Input validation | Reject request on parse error | Pass raw input to backend |
| Rate limiter | Block request if limiter state unknown | Allow request through |

### Real-World Engineering Scenario

**Scenario:** An API gateway that caches authorization decisions for performance.

```python
# Fail-OPEN (insecure)
def check_permission(user, resource):
    try:
        allowed = auth_service.check(user, resource)
        return allowed
    except AuthServiceTimeout:
        return True  # ❌ Fail open — grants access when auth is down

# Fail-CLOSED (secure)
def check_permission(user, resource):
    try:
        allowed = auth_service.check(user, resource)
        return allowed
    except AuthServiceTimeout:
        return False  # ✅ Fail closed — denies access on error
```

The fail-open version may seem "user-friendly" (no one gets locked out), but it is exactly what attackers exploit: trigger a DoS on the auth service, then walk through the gate.

### Exceptions

There are narrow cases where fail-open is acceptable — for example, a content-delivery network serving static assets: if the authorization check fails, serving the public asset is still safe because it was already public. Document every exception explicitly in an ADR.

---