---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "5. Design Patterns for Security"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 19/25
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