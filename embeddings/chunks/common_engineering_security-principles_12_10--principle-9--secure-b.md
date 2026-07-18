---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "10. Principle 9: Secure by Default"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 12/14
---

## 10. Principle 9: Secure by Default

**"The default configuration of a system should be secure, and the decision to reduce security must be an explicit, informed choice."**

### What It Means

When a user installs software, creates a service, or deploys an application, the default settings should be the secure settings. If a default is insecure, most users will never change it. This principle is violated every time a product ships with default passwords, open ports, disabled encryption, or permissive CORS policies.

### Secure vs Insecure Defaults

| Configuration | Secure Default | Insecure Default |
|---|---|---|
| Admin password | Force change on first login | `admin/admin` |
| TLS | Enforce TLS 1.2+ | Allow cleartext or TLS < 1.2 |
| CORS | Deny all origins | Allow all origins (`*`) |
| File permissions | Restrictive (0700) | Permissive (0777) |
| Debug endpoints | Disabled in production | Enabled by default |
| Session cookies | `HttpOnly`, `Secure`, `SameSite=Lax` | Plain cookies |
| API keys | Require authentication | Public access |

### Real-World Engineering Scenario

**Scenario:** A new microservice framework is created by an internal platform team. The scaffold generator creates a new service with:

- Debug mode **enabled** (shows stack traces, env vars, database queries on error pages)
- CORS `Access-Control-Allow-Origin: *`
- No authentication middleware on any endpoint
- Default database user with full DDL permissions
- Health endpoint on the same port as production traffic

Every new service built from this scaffold is immediately vulnerable until an engineer *manually* hardens it. Most teams never get around to it.

**Fix:** The scaffold generates a service that:
- **Fails closed** — everything is denied by default
- **Requires explicit opt-in** for CORS, debug mode, and permissive settings
- **Bakes in authentication** — all endpoints require a valid token unless explicitly marked as public with an architectural review

### Implementation Checklist

- [ ] No default passwords — force credential creation or rotation on first use
- [ ] No listening on `0.0.0.0` without explicit configuration — bind to `127.0.0.1` for internal services
- [ ] Encryption enabled by default (TLS for transport, encryption at rest for storage)
- [ ] Logging and auditing enabled by default
- [ ] Rate limiting and resource quotas enabled by default
- [ ] Administrative interfaces not exposed on public network interfaces
- [ ] "Secure configuration" guide is shorter than the "how to turn off security" guide

---