---
source: "common/api-security/rest-api-security.md"
title: "REST API Security"
heading: "3. Pagination Security"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, authentication, limiting, methods, overview, pagination, rate, security, table]
chunk: 6/9
---

## 3. Pagination Security

Pagination vulnerabilities can expose data through:

- **Mass Assignment** — manipulating `limit`/`offset` to extract all records
- **Cursor-based IDOR** — guessing/iterating sequential cursors
- **Timing Attacks** — inferring data existence through response timing
- **Sort Injection** — manipulating sort parameters for SQL injection

### Vulnerable Code (Unbounded Pagination)

```python
# VULNERABLE: Unbounded pagination — attacker can dump entire DB
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)  # No max bound!
    
    users = db.execute(
        "SELECT id, email, name FROM users LIMIT ? OFFSET ?",
        (limit, (page - 1) * limit)
    ).fetchall()
    
    return jsonify(users)
```

### Secure Code (Bounded Pagination)

```python
# SECURE: Bounded pagination with max limit and authorization check
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    limit = min(request.args.get('limit', 50, type=int), 100)  # Hard cap
    
    if page < 1 or limit < 1:
        return jsonify(error="Invalid pagination params"), 400
    
    # Authorization: only return users the caller is allowed to see
    if not current_user.can_view_users():
        return jsonify(error="Insufficient permissions"), 403
    
    users = db.execute(
        "SELECT id, email, name FROM users LIMIT ? OFFSET ?",
        (limit, (page - 1) * limit)
    ).fetchall()
    
    # Return total count for transparency (but rate-limit this endpoint)
    total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    return jsonify({
        "data": users,
        "page": page,
        "limit": limit,
        "total": total
    })
```

---