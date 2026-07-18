# Secure by Design

> **Audience:** Software engineers, architects, product managers
> **Purpose:** Embedding security into architecture and design decisions, not bolting it on after the fact
> **Reading time:** 15–20 minutes

---

## Table of Contents

1. [What "Secure by Design" Means](#1-what-secure-by-design-means)
2. [Security Requirements Engineering](#2-security-requirements-engineering)
3. [Architecture Decision Records for Security](#3-architecture-decision-records-for-security)
4. [Trade-off Analysis](#4-trade-off-analysis)
5. [Design Patterns for Security](#5-design-patterns-for-security)
6. [Secure Defaults](#6-secure-defaults)
7. [Fail Securely vs Fail Open](#7-fail-securely-vs-fail-open)
8. [Input Validation at Trust Boundaries](#8-input-validation-at-trust-boundaries)
9. [Secure by Design in Practice: A Worked Example](#9-secure-by-design-in-practice-a-worked-example)
10. [References](#10-references)
11. [Further Reading](#11-further-reading)

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

## 3. Architecture Decision Records for Security

Architecture Decision Records (ADRs) document significant architectural decisions, including the context, alternatives considered, trade-offs, and the final decision. Security ADRs are critical because they capture *why* a security decision was made — knowledge that is lost when the engineer who made the decision leaves.

### Security ADR Template

```markdown
# ADR-NNN: [Title]

## Status
[Proposed | Accepted | Deprecated | Superseded-by ADR-NNN]

## Context
[What is the engineering problem? What security concern prompted this decision?]
[What is the threat landscape? What data is at stake?]

## Decision
[What security control or architecture pattern was chosen?]
[How does this control mitigate the identified threats?]

## Alternatives Considered
| Alternative | Why Rejected |
|---|---|
| [Option A] | [Risk too high / performance impact / not compliant] |
| [Option B] | [Doesn't meet requirements / too complex to maintain] |

## Consequences
[What is the security benefit? What is the cost — performance, complexity, usability?]
[What residual risk remains?]

## Compliance Mapping
[Which regulatory controls does this decision satisfy?]
```

### Example Security ADR

```markdown
# ADR-017: Token-Based Authentication Using OAuth 2.0 + JWT

## Status
Accepted

## Context
The new customer-facing API needs authentication. We evaluated session cookies
vs token-based auth. The threat model identified spoofing (STRIDE-S) as the
primary concern: an attacker who steals a session cookie can impersonate any user.

## Decision
Use OAuth 2.0 with JWT access tokens. Access tokens expire in 15 minutes;
refresh tokens expire in 7 days and are stored in an HttpOnly, Secure, SameSite=Strict cookie.

## Alternatives Considered
| Alternative | Why Rejected |
|---|---|
| Session cookies with server-side sessions | Requires stateful session store; horizontal scaling complexity |
| API keys | No user identity binding; key rotation is manual |
| Mutual TLS | Operational complexity beyond current team capacity; not yet supported by clients |

## Consequences
+ Short-lived tokens limit the blast radius of token theft
+ Stateless — no session DB to scale or secure
− Token revocation requires a deny-list (short TTL mitigates this)
− JWT library must be kept up to date (critical for alg confusion attacks)

## Compliance Mapping
PCI-DSS 8.3 (secure authentication), OWASP ASVS V2 (authentication verification)
```

### When to Write a Security ADR

- Choosing an authentication strategy
- Deciding on an encryption scheme or key management approach
- Introducing a new trust boundary or changing an existing one
- Selecting a third-party security vendor / service
- Making a trade-off that reduces security in one area for gain in another
- Responding to an incident that changes the security posture

---

## 4. Trade-off Analysis

Security never exists in a vacuum. Every security control imposes costs — performance, latency, complexity, usability, operational burden. Engineering leadership requires making explicit, documented trade-offs.

### Common Trade-offs

| Security Concern | Trade-off | Decision Framework |
|---|---|---|
| Encryption at rest | Performance overhead per query | Encrypt sensitive columns only; use application-level encryption for PII, TDE for compliance |
| MFA for all users | Friction in user onboarding | Risk-based MFA: prompt only on new devices or sensitive operations |
| Complete mediation (every access checked) | Increased latency for every request | Cache authorization decisions for short TTL; invalidate on permission change |
| Network micro-segmentation | Operational complexity of managing many security groups | Use service mesh (Istio/Linkerd) for policy-as-code; start with coarse segmentation, refine |
| Input validation on every input | Development velocity | Use framework-level validation (e.g., Zod, Pydantic) to reduce per-endpoint boilerplate |
| FIPS-validated cryptography | Limited algorithm choices, slower implementations | Use FIPS-compatible libraries in user-space; accept performance impact for compliance |

### The Trade-off Canvas

When evaluating a security design decision, use this canvas:

```
┌──────────────────────────────────────────────────┐
│ Decision: ______________________________________ │
├──────────────────────────────────────────────────┤
│ Security Benefit │ Cost │
│ ┌───────────────┐ │ ┌──────────┐ │
│ │ What threats  │ │ │Performance│ │
│ │ are mitigated?│ │ │Complexity │ │
│ │ What is the   │ │ │Usability  │ │
│ │ risk reduction?│ │ │Ops burden │ │
│ └───────────────┘ │ │Cost ($)   │ │
│                    │ └──────────┘ │
├──────────────────────────────────────────────────┤
│ Residual Risk After This Control │
│ ┌──────────────────────────────────────────────┐ │
│ │ What threats are NOT mitigated? │ │
│ │ What is the accepted risk level? │ │
│ └──────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────┤
│ Review Date: ______  Reviewer: ______ │
└──────────────────────────────────────────────────┘
```

### Guiding Principles for Trade-offs

- **Explicit beats implicit** — document the trade-off, don't let it happen by accident
- **Risk-based, not fear-based** — don't apply controls because "everyone says to" — understand the specific threat they address
- **Proportional** — the cost of a control should not exceed the value of the asset it protects
- **Reversible** — prefer controls that can be tightened or loosened without architectural changes

---

## 5. Design Patterns for Security

Design patterns are reusable solutions to recurring problems. Several classic GoF patterns have direct security applications.

### 5.1 Guard Pattern

**Purpose:** Gate access to a resource based on a condition, before the operation executes.

```python
class EditNoteGuard:
    """Guard: check ownership before allowing edit."""
    def __init__(self, note_repo, audit_log):
        self.note_repo = note_repo
        self.audit_log = audit_log

    def check(self, user_id, note_id):
        note = self.note_repo.find_by_id(note_id)
        if note is None:
            self.audit_log.log("edit_note.not_found", user_id, note_id)
            raise NotFoundError("Note not found")
        if note.owner_id != user_id:
            self.audit_log.log("edit_note.unauthorized", user_id, note_id)
            raise ForbiddenError("You do not own this note")
        return note  # Guard passed, proceed with edit
```

**Security benefit:** Centralizes authorization logic in one place, making it auditable and testable. Every guarded operation follows the same pattern.

**When to use:** Any operation that depends on user identity, resource ownership, or role membership.

### 5.2 Proxy Pattern (Access Control)

**Purpose:** A surrogate object that controls access to the real object. In security, a proxy intercepts every call to perform authentication, authorization, rate limiting, or logging.

```python
class AuthorizationProxy:
    """Proxy: intercepts all calls to check authorization."""
    def __init__(self, real_service, auth_service):
        self._real = real_service
        self._auth = auth_service

    def __getattr__(self, name):
        method = getattr(self._real, name)
        if not method:
            raise AttributeError(name)
        def secured_method(*args, **kwargs):
            # Authorization check before every method call
            if not self._auth.check_permission(
                user=kwargs.get("user"),
                action=name,
                resource=kwargs.get("resource_id")
            ):
                raise ForbiddenError("Access denied")
            return method(*args, **kwargs)
        return secured_method
```

**Security benefit:** Separates authorization from business logic. The service object never needs to know about security — the proxy handles it.

**When to use:** In service-oriented architectures where you want to layer security without modifying service code. API gateways are a real-world example of the security proxy pattern.

### 5.3 Observer Pattern (Audit Logging)

**Purpose:** A subject maintains a list of observers that are notified when state changes. For security, observers can log every state change for audit purposes.

```python
class ObservableDocument:
    def __init__(self, doc_id):
        self.doc_id = doc_id
        self._content = ""
        self._observers = []

    def attach(self, observer):
        self._observers.append(observer)

    def update_content(self, new_content, user_id):
        old_content = self._content
        self._content = new_content
        # Notify all observers (audit log, indexer, etc.)
        for observer in self._observers:
            observer.on_update(self.doc_id, user_id, old_content, new_content)
```

**Security benefit:** Decouples audit logging from business logic. You can add, remove, or change audit destinations (local file, centralized SIEM, blockchain-based log) without changing the document model.

**When to use:** Any system where data mutation must be logged — document stores, financial systems, healthcare records, CI/CD pipelines.

### 5.4 Facade Pattern (API Security Boundary)

**Purpose:** A unified interface to a complex subsystem. In security, the facade is the *only* entry point — all requests go through it, no internal components are directly reachable.

```python
class PaymentFacade:
    """Facade: the only public entry point for payment operations."""
    def process_payment(self, user_id, amount, payment_method):
        # All security checks in one place
        self._rate_limiter.check(user_id)
        user = self._auth.authenticate(user_id)
        self._fraud_check.run(user, amount, payment_method)
        # Internal subsystem — never exposed directly
        token = self._payment_gateway.create_token(payment_method)
        charge = self._payment_gateway.charge(token, amount)
        self._audit_log.log_payment(user_id, amount, charge.id)
        return charge
```

**Security benefit:** The facade creates a narrow, well-defined attack surface. Internal components have no public endpoints and cannot be misused individually.

**When to use:** As an anti-corruption layer between your system and third-party services; as the public API boundary of a microservice.

### Pattern Selection Guide

| Pattern | Security Function | Best For |
|---|---|---|
| Guard | Pre-condition authorization | CRUD operations, resource access |
| Proxy | Interception-based security | API gateways, service meshes |
| Observer | Audit and monitoring | Compliance logging, SIEM integration |
| Facade | Attack surface reduction | Microservice boundaries, third-party integrations |

---

## 6. Secure Defaults

If a default is insecure, most users will never change it. This is not a user problem — it is a design problem.

### The Secure-Defaults Checklist

| Area | Insecure Default | Secure Default |
|---|---|---|
| **Web framework** | Debug mode on, CORS `*`, session without `HttpOnly` | Debug off, CORS explicit origins, `HttpOnly+Secure+SameSite` |
| **Database** | Default admin password, network `0.0.0.0` | No default password (force on setup), listen on localhost |
| **Container** | Root user, all capabilities, writable rootfs | Non-root user, drop all caps, read-only rootfs |
| **API** | No authentication, no rate limiting | Auth required, rate limiting enabled |
| **Cloud resource** | Public bucket, open security group | Private by default, least-privilege policies |
| **Secret management** | Secrets in config files, `.env` in repo | Secrets from vault/secret manager, `.env` in `.gitignore` |
| **Logging** | Logging off, sensitive data in logs | Structured logging, PII redaction enabled |
| **TLS** | TLS disabled, allows TLS < 1.2 | TLS 1.2+ required, HSTS enabled |
| **Backup** | Unencrypted backups | Encrypted backups with separate key |
| **Dependencies** | Auto-update off, no integrity check | Dependency scanning, lock files, SBOM generation |

### Engineering Secure Defaults

- **Scaffold generators** — `npm create`, `dotnet new`, `rails new` should generate secure-by-default projects
- **Configuration validation** — the application should refuse to start with insecure settings, not run with a warning
- **Hardening guides** — if you must document a list of "things to change for production", you failed at secure defaults

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

## 8. Input Validation at Trust Boundaries

Input validation is not just about preventing injection attacks — it is about enforcing the *shape* of data at every trust boundary. Every interface between different trust zones must validate.

### Trust Boundary Validation Rules

```
Trust Boundary A                          Trust Boundary B
┌─────────────┐      Input Validation     ┌─────────────┐
│   External   │ ──── 1. Reject invalid ──→ │   Internal   │
│   (untrusted) │      2. Sanitize/escape    │   (trusted)   │
│              │      3. Log anomalies       │              │
└─────────────┘                             └─────────────┘
```

### What to Validate at Each Boundary

| Boundary | Validate | Reject |
|---|---|---|
| HTTP → Web app | Content-Type, Content-Length, query params, headers | Oversized payloads, unexpected Content-Type, binary data in text fields |
| Web app → Database | Parameter types, length, encoding | SQL metacharacters (handled by parameterized queries) |
| Web app → Message queue | Message schema, field types, max depth | Messages exceeding schema definition |
| Service A → Service B (mTLS) | JWT claims, call context, request payload schema | Expired/revoked tokens, schema violations |
| API → Third-party service | Response schema, status codes, max response size | Unexpected response structure |
| User input → File system | File name, file type, file size | Path traversal patterns (`../`, null bytes), executable extensions |

### Validation Strategy: Allow-list

**Whitelist (allow-list):** Define exactly what is allowed, reject everything else.

```python
ALLOWED_ROLES = {"viewer", "editor", "admin"}
def validate_role(role):
    if role not in ALLOWED_ROLES:
        raise ValueError(f"Invalid role: {role}")
    return role
```

**Blacklist (deny-list):** Define what is forbidden, allow everything else.

```python
BLOCKED_PATHS = {"../../etc/passwd", "..\\..\\windows\\system32"}
def validate_path(path):
    for blocked in BLOCKED_PATHS:
        if blocked in path:
            raise ValueError(f"Path contains blocked pattern")
    return path
```

> **Always prefer allow-lists over deny-lists.** You can enumerate what's valid; you cannot enumerate everything invalid.

---

## 9. Secure by Design in Practice: A Worked Example

**Scenario:** Building a document-sharing platform — users upload PDFs and share them via links.

### Phase 1: Requirements (SbD from Sprint 1)

**Business requirements:**
- Users upload PDFs (up to 50 MB)
- Documents are shared via unique, unguessable links
- Only the uploader can delete a document

**Security requirements derived:**
- In-transit encryption (TLS) — all traffic
- At-rest encryption — PDF content encrypted in S3
- Access control — only the uploader can delete; anyone with the link can view
- Input validation — file type validation, virus scanning, path sanitization
- Audit log — every upload, share, and delete is logged

### Phase 2: Architecture Decisions

| Decision | Security Concern | Chosen Approach |
|---|---|---|
| File storage | Where does the PDF live? | S3 with bucket policies restricted to the application role |
| Link generation | How to make links unguessable? | 256-bit random tokens (crypto/rand), not sequential IDs |
| Download auth | How to authorize a download? | Token in URL = implicit authorization; no additional auth for viewers |
| Deletion auth | How to authorize a delete? | Uploader's JWT must match the owner stored with the document |
| Virus scanning | How to handle malicious uploads? | ClamAV scan on upload; reject if infected; scanned-async for large files |

### Phase 3: Design Patterns Applied

- **Guard pattern** on every `DeleteDocument` operation (owner check)
- **Proxy pattern** on the S3 download handler (verifies the share link is active and not expired)
- **Observer pattern** on upload and delete events (audit logging, notification to uploader)
- **Facade pattern** — `DocumentService` is the only public interface; S3 and database are internal

### Phase 4: Trade-offs

| Trade-off | Decision | Rationale |
|---|---|---|
| Link sharing vs auth | No auth on view — anyone with the link can see the doc | Business requirement; mitigated by link unpredictability and optional expiry |
| File scanning latency | Upload response time vs security | Accept higher latency for all files up to 10 MB; async scan for 10–50 MB files |
| Encryption at rest | Server-side vs client-side encryption | Server-side with KMS; client-side adds complexity and prevents server-side search/indexing |

### Phase 5: Secure Defaults

- All new buckets are private by default
- Share links default to expiring in 7 days (configurable, never "never expires")
- Upload endpoint defaults to 10 MB limit with explicit override
- All audit logging is enabled by default and cannot be disabled by tenants

---

## 10. References

### OWASP Application Security Verification Standard (ASVS)

OWASP ASVS provides a tiered set of security requirements for web applications:

| Level | Description | When to Target |
|---|---|---|
| L1 | Automated verification — basic vulnerabilities | All applications |
| L2 | Manual verification — standard defenses | Applications handling sensitive data |
| L3 | Advanced verification — defense in depth | Critical applications (fintech, healthcare, infrastructure) |

**Key ASVS sections for design:**
- V2: Authentication Verification Requirements
- V3: Session Management Verification Requirements
- V4: Access Control Verification Requirements
- V5: Validation, Sanitization and Encoding
- V8: Data Protection
- V14: Configuration

### NIST SP 800-160 Vol. 1 (Systems Security Engineering)

NIST's framework for integrating security into systems engineering:
- Part 2: Security design principles
- Part 3: Risk management in design
- Appendix F: Security design pattern catalog

### CISA Secure by Design

CISA's 2023 "Secure by Design" pledge — principles for software manufacturers:
1. **Take ownership of security outcomes** — ship secure, not just "fast"
2. **Embrace radical transparency** — publish vulnerability data, don't hide it
3. **Lead from the top** — executives own security, not just the CISO

### Additional References

- **MITRE CWE-TOP 25** — design-level weakness patterns to avoid
- **NIST SP 800-53 Rev 5** — comprehensive control catalog for federal systems
- **ISO 27001:2022 Annex A** — control set for information security management
- **Cloud Security Alliance (CSA) Cloud Controls Matrix** — cloud-specific design controls

---

## 11. Further Reading

- **"Software Security: Building Security In"** by Gary McGraw — classic text on the "touchpoints" of secure development
- **"Secure by Design"** by Dan Bergh Johnsson, Daniel Deogun, and Daniel Sawano — practical guidance on writing secure code from the ground up
- **OWASP Cheat Sheet Series** — condensed, actionable design guidance for specific security topics
- **NIST SSDF (SP 800-218)** — Secure Software Development Framework, a US government standard for secure development

---

> **Key Takeaway:** "Secure by Design" is not a feature you add — it is a way of thinking about architecture. Every pattern, every default, every trade-off is a security decision. The goal is not to eliminate all risk (impossible) but to ensure that every risk taken is an *informed* risk, explicitly documented, and consciously accepted.
