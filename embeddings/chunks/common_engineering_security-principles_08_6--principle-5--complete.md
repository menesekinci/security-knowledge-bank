---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "6. Principle 5: Complete Mediation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 8/14
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