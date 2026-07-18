---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "SQL Injection"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 4/11
---

## SQL Injection

### How It Works

An attacker manipulates SQL queries by inserting special characters (`'`, `"`, `--`, `;`) that change the query structure.

### Vulnerable Code Examples

**Python (Flask) — Vulnerable**
```python
from flask import Flask, request
import sqlite3

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # 🔴 VULNERABLE: string concatenation
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query).fetchall()
```
**Attack:** `?id=' OR '1'='1` → returns ALL users
**Attack:** `?id='; DROP TABLE users;--` → deletes the table

**Node.js (Express + pg) — Vulnerable**
```javascript
const { Pool } = require('pg');
const pool = new Pool();

app.get('/user', async (req, res) => {
    const id = req.query.id;
    // 🔴 VULNERABLE
    const result = await pool.query(`SELECT * FROM users WHERE id = '${id}'`);
    res.json(result.rows);
});
```

**Java (JDBC) — Vulnerable**
```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Fixed Code Examples

**Python (Flask) — Fixed**
```python
from flask import Flask, request
import sqlite3

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # ✅ SAFE: parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query, (user_id,)).fetchall()
```

**Node.js (Express + pg) — Fixed**
```javascript
app.get('/user', async (req, res) => {
    const id = req.query.id;
    // ✅ SAFE: parameterized query
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    res.json(result.rows);
});
```

**Java (JDBC) — Fixed**
```java
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM accounts WHERE custID = ?"
);
stmt.setString(1, request.getParameter("id"));
ResultSet rs = stmt.executeQuery();
```

---