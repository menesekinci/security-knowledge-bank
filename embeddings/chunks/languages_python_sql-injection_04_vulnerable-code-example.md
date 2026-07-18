---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Classic Authentication Bypass

```python
# 🚫 VULNERABLE — AI-generated login
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # AI concatenates credentials into query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return 'Login successful'
    return 'Login failed'

# Attacker sends: username = admin' --
# Password can be anything
# Query becomes: SELECT * FROM users WHERE username = 'admin' --' AND password = 'x'
# Bypasses authentication!
```

### Second-Order SQL Injection

```python
# 🚫 VULNERABLE — AI-generated second-order SQLi
def update_user_profile(user_id, bio):
    # First read existing data (safe, parameterized)
    user = db.session.execute(
        text("SELECT * FROM users WHERE id = :uid"), 
        {"uid": user_id}
    ).fetchone()
    
    # Then use data in another query unsafely
    name = user['name']  # Could contain SQL from a previous injection
    db.session.execute(
        text(f"UPDATE users SET bio = '{bio}' WHERE name = '{name}'")  # 💥
    )
```

---