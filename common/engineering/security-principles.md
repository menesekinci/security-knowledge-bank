# Security Engineering Principles

> **Audience:** Software engineers, architects, infrastructure engineers
> **Purpose:** Foundational security principles that guide engineering decisions across the SDLC
> **Reading time:** 15–20 minutes

---

## Table of Contents

1. [Why Principles Matter](#1-why-principles-matter)
2. [Principle 1: Defense in Depth](#2-principle-1-defense-in-depth)
3. [Principle 2: Least Privilege](#3-principle-2-least-privilege)
4. [Principle 3: Fail Safe](#4-principle-3-fail-safe)
5. [Principle 4: Economy of Mechanism](#5-principle-4-economy-of-mechanism)
6. [Principle 5: Complete Mediation](#6-principle-5-complete-mediation)
7. [Principle 6: Open Design](#7-principle-6-open-design)
8. [Principle 7: Least Common Mechanism](#8-principle-7-least-common-mechanism)
9. [Principle 8: Psychological Acceptability](#9-principle-8-psychological-acceptability)
10. [Principle 9: Secure by Default](#10-principle-9-secure-by-default)
11. [Applying Principles Together](#11-applying-principles-together)
12. [Further Reading](#12-further-reading)

---

## 1. Why Principles Matter

Security principles are not abstract theory — they are decision-making heuristics hardened by decades of real-world failures. Every vulnerability in production can be traced back to the violation of one or more of these principles. Internalizing them lets engineers make sound security trade-offs without needing a security expert in every room.

These nine principles are drawn from Saltzer & Schroeder's seminal 1975 paper *"The Protection of Information in Computer Systems"* and extended with modern engineering practice. They apply equally to REST APIs, serverless functions, microservice meshes, IoT firmware, and AI agent pipelines.

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

## 5. Principle 4: Economy of Mechanism

**"Keep the design as simple and small as possible. Complexity is the enemy of security."**

### What It Means

Every line of code, every configuration knob, every integration point is an opportunity for a vulnerability. Smaller, simpler designs have fewer bugs, are easier to audit, and are more likely to be correctly implemented.

### The Complexity-Vulnerability Curve

```
Vulnerability Density
        ↑
        |                       /
        |                     /
        |                   /
        |                 /
        |               /
        |             /
        |           /
        |─────────/─────── Complex baseline
        |         /
        |       /
        |     /
        |   /
        | /
        +──────────────────────────→ Code/Config Complexity
```

### Real-World Engineering Scenario

**Scenario:** Two approaches to authorization middleware.

**Complex approach:** A custom rules engine that evaluates user attributes, resource tags, time windows, and geolocation via a JSON DSL with 14 different operators. Six engineers maintain 9,000 lines of evaluator code. Three bugs found in production in the last quarter — two were bypassable.

**Simple approach:** Four well-defined roles with explicit allow-lists. The policy is 200 lines of configuration. Any engineer can read it and verify correctness. Extensions are rare and reviewed in depth.

The simpler system is not only easier to secure — it is actually more *capable* because its correctness is verifiable.

### Practical Tactics

- Prefer **whitelists** over blacklists (you can enumerate what's allowed, but never what's forbidden)
- Choose **well-audited frameworks** over custom implementations (don't write your own crypto, auth, or serialization)
- **Remove dead code** — every unused endpoint, feature flag, and config parameter is a potential attack surface
- **Composability over monoliths** — small single-purpose components are easier to reason about

---

## 6. Principle 5: Complete Mediation

**"Every access to every object must be checked for authorization on every access."**

### What It Means

No caching of authorization decisions. No "check once, trust forever" patterns. No skipping checks because "the caller already authenticated." Every request, every time.

### Pattern: The Check-Once Trap

```python
# ❌ BAD: Check at login, then never again
def login(request):
    user = authenticate(request)
    session["user_id"] = user.id
    session["role"] = user.role  # Stored, never re-verified

def admin_panel(request):
    user_id = session["user_id"]
    role = session["role"]  # Role from login — what if it changed?
    if role == "admin":
        return sensitive_data()
    return 403
```

```python
# ✅ GOOD: Check on every access
def admin_panel(request):
    user_id = session["user_id"]
    user = load_user(user_id)  # Fresh lookup every time
    if user.role == "admin":
        return sensitive_data()
    return 403
```

### When Mediation Breaks

- **Cached permission sets** — user was admin yesterday, got demoted today, but the cache still says admin
- **Path traversal** — a URL rewrite normalizes `/../secret` but the access check runs on the raw path, not the resolved one
- **Client-side checks** — hiding an "admin" button in the UI is not authorization; the API still needs to check
- **Batch operations** — checking permission on the first item of a batch then assuming all subsequent items are allowed

### Real-World Engineering Scenario

**Scenario:** A document storage API with shared folders.

A user has View permission on Folder A but not on Folder B. They call `GET /api/documents?folder=B`. The API:

1. Authenticates the request — ✅
2. Resolves folder B's documents from the database
3. Checks view permission on Folder B — ✅ Complete mediation
4. Returns only documents the user can access — for paginated results, *every page checks permissions again*

Without step 3, a user who can reach the document service can see any document. Complete mediation ensures permission is verified at the resource level, not just the entry point.

---

## 7. Principle 6: Open Design

**"The security of a mechanism should not depend on the secrecy of its design or implementation."**

### What It Means

Security through obscurity — hiding source code, using secret algorithms, or relying on undocumented protocols — is not a real control. A system should remain secure even when an attacker knows every detail of its design, except for secrets like passwords and cryptographic keys (Kerckhoffs's principle).

### Common Obscurity Traps

| Obscurity Tactic | Why It Fails |
|---|---|
| Hiding API endpoints (`/secret-admin-panel`) | Discoverable via directory enumeration, web crawlers, or JS source maps |
| Proprietary encryption | Reverse engineering reveals the algorithm; amateur crypto is broken quickly |
| Obfuscated source code | Determined attackers deobfuscate; it only slows down casual inspection |
| Security-through-URL-secrecy | URLs appear in browser history, logs, referrer headers, and bookmarks |
| Custom protocols | Fuzzing and traffic analysis reverse-engineer the protocol faster than you think |

### Why Open Design Works

1. **Public scrutiny finds bugs faster** — open-source libraries like OpenSSL, Curve25519, and OWASP libraries are stronger because they are reviewed by thousands of eyes.
2. **Standard protocols are well-tested** — TLS, OAuth 2.0, and SAML have been attacked for years; their attack surface is well-understood.
3. **Cryptographic security is mathematical, not secret** — AES and SHA-256 are fully public. Their security comes from the hardness of the underlying math, not from hiding the algorithm.
4. **Third-party audits are meaningful** — you cannot get a meaningful security audit of a closed system because the auditor cannot verify what they cannot see.

### Real-World Engineering Scenario

**Scenario:** A startup builds a proprietary authentication protocol because "JWT is too complex." They keep the protocol specification internal.

The protocol has a padding oracle vulnerability discovered during a penetration test. Because the implementation is closed, no community tooling exists to detect the vulnerability, no security researchers can warn other users, and the fix cycle depends entirely on the internal team recognizing the problem.

Had they used standard JWT with well-known libraries, the attack surface would be documented, monitored, and tested by thousands of projects worldwide.

### Nuance

Open design does NOT mean publishing secrets. Cryptographic keys, database passwords, API tokens, and internal network topology are secrets. The *protocols and algorithms* are public. Open design also does not mandate open-source — but open-source projects benefit disproportionately from the principle.

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

## 9. Principle 8: Psychological Acceptability

**"It is essential that the human interface be designed for ease of use, so that users routinely and automatically apply the protection mechanisms correctly."**

### What It Means

If security is harder than insecurity, users will bypass it. A perfectly secure system that nobody uses correctly provides zero security. Security controls that frustrate users create workarounds that are worse than having no control at all.

### The Security-Usability Trade-off Spectrum

```
Perfect Security           Perfect Usability
    │                            │
    │   ┌──────────────────┐    │
    │   │  Overly complex   │    │
    │   │  → Users bypass   │    │
    │   └──────────────────┘    │
    │         ┌──────────┐      │
    │         │  Optimal │      │
    │         │  Balance │      │
    │         └──────────┘      │
    │   ┌──────────────┐        │
    │   │ Too simple   │        │
    │   │ → Not secure │        │
    │   └──────────────┘        │
```

### Real-World Engineering Scenario

**Scenario:** Password policy.

**Bad (violates psychological acceptability):**
- 14+ characters, must include uppercase, lowercase, digit, symbol, no repeating characters, no dictionary words
- Must change every 30 days
- Cannot reuse any of the last 24 passwords
- Two-factor authentication that sends codes via email (easy to miss)

Engineers respond by writing passwords on sticky notes, using password patterns (`April2024!`, `May2024!`), or saving passwords in unprotected spreadsheets.

**Better (respects psychological acceptability):**
- Encourage passphrases (length over complexity)
- Support password managers (long API token, WebAuthn, passkeys)
- Risk-based MFA — only prompt for 2FA on suspicious logins or sensitive operations
- Clear, actionable error messages: "This password appears in known breaches — choose another" vs "Password does not meet policy requirements"

### Practical Guidelines

- **Security should be the default path** — the secure action should also be the easiest action
- **Progressive security** — prompt for additional verification only on high-risk operations (new device, large transfer, privilege change)
- **Clear feedback** — tell the user *why* something was blocked and *what they can do about it*
- **Recoverability** — locked-out users should have a clear, non-humiliating recovery path
- **Developer empathy** — engineers are users too. SDKs and APIs should have secure defaults and obvious "right ways" to do things

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

## 11. Applying Principles Together

No principle operates in isolation. They interact — sometimes reinforcing, sometimes conflicting. The art of security engineering is balancing them.

### Tensions

| Principles | Tension | Resolution |
|---|---|---|
| Least Privilege vs Psychological Acceptability | Strict permissions frustrate users | Use JIT elevation — access is restricted by default but easy to request temporarily |
| Economy of Mechanism vs Defense in Depth | Simplicity says one control; layered defense says many | Layer different *kinds* of controls, not redundant copies of the same one |
| Complete Mediation vs Performance | Checking every access is slow | Cache authorization decisions for short TTLs and invalidate on permission changes |
| Open Design vs Least Common Mechanism | Open APIs are shared by nature | Design APIs with per-tenant isolation and explicit scopes |

### Decision Heuristic

When evaluating a security design decision, ask:

1. **Which principles does this decision honor?** (List them.)
2. **Which principles does this decision violate?** (Be honest — no design is perfect.)
3. **Is the violation explicit and documented?** (It should be in an ADR or design doc.)
4. **Is the violation mitigated by another principle?** (E.g., violating Economy of Mechanism with a more complex authorization layer might be justified by Least Privilege requirements.)
5. **What is the residual risk after all mitigations?** (No design eliminates all risk — know what's left.)

---

## 12. Further Reading

- **Saltzer & Schroeder (1975),** *"The Protection of Information in Computer Systems"* — the original paper that defined these principles
- **NIST SP 800-160 Vol. 1,** *"Systems Security Engineering"* — modern framework for applying these principles to system engineering
- **OWASP Application Security Verification Standard (ASVS)** — practical checklist for verifying secure design in web applications
- **Jerome Saltzer,** *"Principles of Computer System Design"* — extends security principles to general system design
- **The National Cybersecurity Center of Excellence (NCCoE)** — practical implementation guides for defense in depth

---

> **Key Takeaway:** These nine principles are not checkboxes — they are a decision-making language. When a team can articulate *which* principles their design honors and *which* it knowingly trades off, they have achieved security engineering maturity. Review them at every architecture review, every sprint planning session, and every incident post-mortem.
