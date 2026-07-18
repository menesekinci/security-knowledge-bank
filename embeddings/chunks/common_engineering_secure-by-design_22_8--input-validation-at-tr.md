---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "8. Input Validation at Trust Boundaries"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 22/25
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