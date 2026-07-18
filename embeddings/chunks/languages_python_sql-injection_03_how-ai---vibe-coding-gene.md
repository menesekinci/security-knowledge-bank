---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

### 1. Raw SQL Concatenation (Most Common Pattern)

```python
# 🚫 VULNERABLE — AI-generated raw SQL
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # AI concatenates user input directly into SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 💥 SQLi
    cursor.execute(query)
    return cursor.fetchone()
```

### 2. SQLAlchemy Raw Text() Misuse

```python
# 🚫 VULNERABLE — AI-generated SQLAlchemy raw query
from sqlalchemy import text
from flask import request

def search_products():
    term = request.args.get('q')
    # AI uses text() with f-string — still vulnerable!
    query = text(f"SELECT * FROM products WHERE name LIKE '%{term}%'")  # 💥
    result = db.session.execute(query)
    return result.fetchall()
```

### 3. ORM Filter with String Interpolation (Django)

```python
# 🚫 VULNERABLE — AI-generated Django ORM misuse
from django.db import connection

def get_orders(status):
    # AI bypasses ORM for "complex" queries
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM orders WHERE status = '{status}'")  # 💥
        return cursor.fetchall()
```

### 4. Dynamic ORDER BY / Column Names

AI often generates this pattern because ORMs handle WHERE parameters but not column names:

```python
# 🚫 VULNERABLE — AI-generated dynamic column reference
def list_users(sort_column, sort_order):
    query = f"SELECT * FROM users ORDER BY {sort_column} {sort_order}"  # 💥
    cursor.execute(query)
```

### 5. IN Clause with String Formatting

```python
# 🚫 VULNERABLE — AI-generated IN clause
def get_users_by_ids(id_list):
    # AI formats list into comma-separated string
    ids = ', '.join(id_list)  # 💥 SQLi in each element
    cursor.execute(f"SELECT * FROM users WHERE id IN ({ids})")
```

### Why AI Does This

- **Raw SQL is in AI training data:** ORM code is less common in training data than raw SQL examples
- **ORM syntax varies:** SQLAlchemy, Django ORM, Peewee all have different APIs — AI may not know which to use
- **AI optimizes for "working code":** Raw SQL always works; ORM methods may be wrong
- **Dynamic queries are hard with ORMs:** AI falls back to string building for complex filters

---