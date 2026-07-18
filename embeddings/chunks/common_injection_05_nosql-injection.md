---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "NoSQL Injection"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 5/11
---

## NoSQL Injection

MongoDB, CouchDB, and other NoSQL databases are **not immune** to injection — especially when using `$where`, `$regex`, or JavaScript evaluation.

### Vulnerable Code Examples

**Node.js (MongoDB) — Vulnerable**
```javascript
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // 🔴 VULNERABLE: directly passing user-controlled object
    const user = await db.collection('users').findOne({
        username: username,
        password: password
    });
    // What if username = { "$ne": "" } and password = { "$ne": "" }?
    // Returns FIRST user without knowing credentials!
});
```

**Using `$where` (critical danger)**
```javascript
// 🔴 VULNERABLE: $where evaluates JavaScript
const userInput = req.query.search;
const results = await db.collection('items').find({
    $where: `this.name.startsWith('${userInput}')`
}).toArray();
// Attack: search = "' || sleep(5000) || '"
```

### Fixed Code Examples

```javascript
// ✅ SAFE: validate input types
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).send('Invalid input');
    }
    const user = await db.collection('users').findOne({
        username: username,
        password: password
    });
});

// ✅ SAFE: avoid $where, use $regex with escaped input
const escaped = userInput.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const results = await db.collection('items').find({
    name: { $regex: `^${escaped}` }
}).toArray();
```

---