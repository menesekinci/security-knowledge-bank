---
source: "common/idor.md"
title: "Insecure Direct Object References (IDOR)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, fixed, uuids, vibe, vulnerable, what]
---

# Insecure Direct Object References (IDOR)

**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-862 (Missing Authorization)
**OWASP Top 10:2021:** A01 — Broken Access Control
**CWE Top 25 2024:** #9 (Missing Authorization)

---

## What Is IDOR?

IDOR occurs when an application exposes **direct references to internal objects** (database IDs, file paths, account numbers) and fails to verify the user's authorization to access those objects. An attacker simply **changes the reference value** to access another user's data.

**Simple explanation:** If user A changes `?user_id=123` to `?user_id=124` and sees user B's private data, that's IDOR.

## Why Vibe Coding Makes This Worse

- **AI assumes "user is = user can access":** AI generates endpoints that fetch data by ID without ownership checks
- **AI focuses on CRUD, not ACL:** AI perfectly generates "get by ID" but forgets "check if this user owns this record"
- **Auto-numbered IDs in AI-generated schemas:** AI uses sequential integers (auto-increment) that are trivially enumerable

## Vulnerable Code Examples

**Python (Flask) — Vulnerable**
```python
@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    # 🔴 VULNERABLE: no ownership check
    invoice = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    return jsonify(invoice)
# User at /invoice/5 can access invoice 6, 7, 8... by changing the URL
```

**Node.js (Express) — Vulnerable**
```javascript
app.get('/api/order/:orderId', async (req, res) => {
    const orderId = req.params.orderId;
    // 🔴 VULNERABLE: no check that this user owns the order
    const order = await db.orders.findById(orderId);
    res.json(order);
});
```

**Java (Spring) — Vulnerable**
```java
@GetMapping("/account/{id}")
public Account getAccount(@PathVariable Long id) {
    // 🔴 VULNERABLE: no authorization check
    return accountRepository.findById(id).orElseThrow();
}
```

## Fixed Code Examples

**Python (Flask) — Fixed**
```python
@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    # ✅ Check user owns this invoice
    invoice = db.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, session['user_id'])
    )
    if not invoice:
        abort(403)  # Forbidden
    return jsonify(invoice)
```

**Node.js (Express) — Fixed**
```javascript
app.get('/api/order/:orderId', async (req, res) => {
    const orderId = req.params.orderId;
    // ✅ Check ownership
    const order = await db.orders.findOne({
        _id: orderId,
        userId: req.session.userId  // Critical authorization check
    });
    if (!order) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(order);
});
```

**Java (Spring) — Fixed**
```java
@GetMapping("/account/{id}")
public ResponseEntity<?> getAccount(@PathVariable Long id, Principal principal) {
    Account account = accountRepository.findById(id).orElseThrow();
    // ✅ Check ownership
    if (!account.getOwner().equals(principal.getName())) {
        return ResponseEntity.status(403).build();
    }
    return ResponseEntity.ok(account);
}
```

## UUIDs Are Not Authorization

```javascript
// 🔴 Using UUID doesn't fix IDOR — attackers can still share/guess UUIDs
app.get('/api/user/:uuid', async (req, res) => {
    // UUID makes it harder to enumerate, but doesn't authorize!
    const user = await db.users.findByUUID(req.params.uuid);
    res.json(user);
});
```

**✅ Use both: unpredictable IDs AND authorization checks.**

## Prevention Checklist for AI Prompts

```
✅ IDOR PREVENTION:
- Every object access must verify the current user's authorization
- Use user-context (session token, JWT) to filter queries, not just URL parameters
- Never rely on obfuscation (UUID, hashids) as a substitute for authorization
- Use attribute-based access control (ABAC) for complex permissions
- Test by fetching resources belonging to other users
- Use random/unguessable IDs as defense-in-depth (not primary defense)
```

## Real-World CVEs

| Vulnerability | CVE |
|---|---|
| Grafana IDOR — authenticated user views other teams' data by iterating `teamId` (CWE-639, CVSS 4.3). Fixed in 7.5.15 / 8.3.5 | CVE-2022-21713 |
| GitLab CE/EE IDOR — authenticated user reads restricted pipeline values via the API (CWE-639, CVSS 3.5). Fixed in 18.6.6 / 18.7.4 / 18.8.4 | CVE-2025-14594 |
| Open WebUI IDOR — authenticated user retrieves another user's private memory via `/api/v1/retrieval/query/collection` (CWE-639, CVSS 4.3). Fixed in 0.8.6 | CVE-2026-29071 |

---

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
