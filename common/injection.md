# Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)

**CWE Categories:** CWE-89 (SQL Injection), CWE-77/78 (Command Injection), CWE-90 (LDAP Injection), CWE-917 (EL Injection), CWE-79 (XSS), CWE-20 (Input Validation)
**OWASP Top 10:2021:** A03 — Injection (274k+ occurrences, 94% of apps tested)
**CWE Top 25 2024:** #1 (XSS), #3 (SQL Injection), #7 (OS Command Injection), #13 (Command Injection)

---

## What Is Injection?

Injection occurs when **untrusted user data is sent to an interpreter** (SQL database, OS shell, LDAP directory, expression parser) as part of a command or query. The attacker's data tricks the interpreter into executing unintended commands or accessing unauthorized data.

**The core rule:** Injection is always a **data vs. code separation** problem. When user input is concatenated directly into a command string, the interpreter can't tell where the developer's code ends and the attacker's data begins.

## Why Vibe Coding Makes This Worse

AI code generators excel at producing working code quickly — but they **default to the simplest path**, which is often string concatenation or template literals. Common AI-generated patterns that introduce injection:

- **String interpolation in SQL:** `SELECT * FROM users WHERE id = '${userId}'` (instead of parameterized queries)
- **`eval()` or `exec()` for flexibility:** AI may reach for dynamic execution to "solve" a problem generically
- **NoSQL queries with `$where`:** AI loves MongoDB's `$where` operator because it's flexible, but it enables JavaScript injection
- **ORM misuse:** AI generates code that builds HQL/JPQL via concatenation instead of parameterized criteria
- **Forgotten input validation:** AI focuses on the "happy path" and omits sanitization

> **💡 Key Insight:** AI models trained on public code have seen millions of *insecure* examples. Without explicit security prompting, they generate the most common pattern — which is often the most vulnerable one.

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

## OS Command Injection

### How It Works

User input is passed to system shell commands without sanitization. The attacker injects command separators (`;`, `|`, `&&`, `` ` ``).

### Vulnerable Code Examples

**Python — Vulnerable**
```python
import subprocess, os

filename = request.args.get('file')
# 🔴 VULNERABLE
os.system(f"cat {filename}")         # Shell injection
subprocess.call(f"cat {filename}", shell=True)  # Also vulnerable
```

**Node.js — Vulnerable**
```javascript
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    // 🔴 VULNERABLE
    exec(`ping -c 4 ${ip}`, (err, stdout) => {
        res.send(stdout);
    });
});
// Attack: ?ip=8.8.8.8; cat /etc/passwd
```

### Fixed Code Examples

```python
# ✅ SAFE: pass args as a list, never shell=True
import subprocess

filename = request.args.get('file')
# Validate filename is a safe path
if not filename or '/' in filename or '..' in filename:
    abort(400)
subprocess.run(["cat", f"/safe/path/{filename}"], shell=False)

# ✅ SAFE: capture output with subprocess.run + an argument list (never os.popen)
# os.popen() takes a STRING and runs it through the shell — a list is wrong AND unsafe
import subprocess
result = subprocess.run(
    ["ls", "-l", filename], shell=False, capture_output=True, text=True
).stdout
```

```javascript
// ✅ SAFE: use execFile or spawn with argument array
const { execFile } = require('child_process');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    // Validate IP address format
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        return res.status(400).send('Invalid IP');
    }
    execFile('ping', ['-c', '4', ip], (err, stdout) => {
        if (err) return res.status(500).send('Ping failed');
        res.send(stdout);
    });
});
```

---

## LDAP Injection

### How It Works

LDAP queries use a filter syntax (`(&(attr=value)(attr2=value2))`). Injecting `*`, `|`, `&`, `!` can bypass authentication or extract data.

### Vulnerable Code

```java
// 🔴 VULNERABLE: string concatenation in LDAP filter
String user = request.getParameter("username");
String filter = "(&(uid=" + user + ")(accountStatus=active))";
// Attack: user = "*" → matches ALL users
// Attack: user = "admin)(|(uid=*" → Bypass auth
DirContext ctx = new InitialDirContext(env);
NamingEnumeration results = ctx.search("dc=example,dc=com", filter, controls);
```

### Fixed Code

```java
// ✅ SAFE: use proper escaping
String user = request.getParameter("username");
// Escape LDAP special characters
user = user.replaceAll("\\*", "\\\\2a")
           .replaceAll("\\(", "\\\\28")
           .replaceAll("\\)", "\\\\29");
String filter = "(&(uid=" + user + ")(accountStatus=active))";
// OR better: use a framework that handles encoding
```

---

## Expression Language (EL) / OGNL Injection

Common in Java applications using Spring, Struts, or JSP. User input that reaches an expression evaluator can execute arbitrary code.

### Vulnerable Code

```java
// 🔴 VULNERABLE: user input evaluated as EL expression
String expression = "${" + userInput + "}";
ExpressionFactory factory = ExpressionFactory.newInstance();
ValueExpression ve = factory.createValueExpression(
    ctx, expression, Object.class
);
ve.getValue(ctx);  // Attack: userInput = "7*7" or worse: "".getClass().forName...
```

### Fixed Code

```java
// ✅ SAFE: don't evaluate user input as expressions
// Use a template engine with auto-escaping (Thymeleaf, Handlebars)
// Never pass raw user input to ExpressionFactory
// If evaluation is required, use a sandboxed evaluator
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| SQLi in Progress MOVEit Transfer | CVE-2023-34362 | Mass data exfiltration (Cl0p ransomware campaign) |
| NoSQLi / access-control bypass in Mongoose | CVE-2019-17426 | Query filter bypass → unauthenticated data access |
| JNDI / expression injection in Log4j (Log4Shell) | CVE-2021-44228 | RCE via JNDI lookup in log messages (not OS command injection) |
| EL Injection in Spring | CVE-2022-22965 (Spring4Shell) | Remote code execution |
| SQLi in WordPress core (`WP_Query`) | CVE-2022-21661 | Unauthenticated disclosure of database contents |

---

## Prevention Checklist for AI Prompts

When asking AI to generate database or shell-interacting code, include these instructions in your prompt:

```
✅ REQUIREMENTS FOR THIS CODE:
- Use parameterized queries / prepared statements for ALL database operations
- NEVER use string concatenation or template literals in SQL/NoSQL queries
- NEVER use $where in MongoDB queries
- Use execFile/spawn with argument arrays instead of exec() with shell:true
- Validate and sanitize ALL user input before processing
- Use an ORM with parameterized queries (SQLAlchemy, Prisma, TypeORM, Hibernate)
- Add input type validation (typeof checks, schema validation with Zod/Joi)
- Escape special characters for the specific interpreter being used
- Do NOT use eval(), new Function(), or setTimeout(string) for dynamic code
- Set Content-Security-Policy headers to mitigate XSS
```

### Quick Decision Tree

```
User input goes into a query/command?
├── SQL database → Use parameterized queries (?, $1, :name)
├── NoSQL query → Use typed objects, avoid $where
├── OS command → Pass arguments as array, no shell=True
├── LDAP filter → Escape special chars or use library
├── EL/OGNL → Never evaluate user input as expressions
└── HTML output → Context-aware encoding (see XSS guide)
```

---

## References

- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP NoSQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Command Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
