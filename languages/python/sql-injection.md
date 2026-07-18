# SQL Injection — Python

> **Severity:** Critical
> **CVSS:** 9.8 (Critical)
> **AI Generation Risk:** Very High — ORM misuse and raw SQL concatenation are common in AI-generated Python

---

## Vulnerability Explanation

SQL Injection (SQLi) occurs when user input is concatenated directly into SQL query strings. In Python, this happens despite the existence of well-designed ORMs (SQLAlchemy, Django ORM, Peewee) because AI models frequently bypass ORM query builders in favor of raw SQL — or use ORM APIs incorrectly.

### Why It Persists in 2025

Despite being one of the oldest documented vulnerabilities, SQLi remains prevalent in AI-generated code because:

- **AI training data is saturated** with tutorials using `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- **Raw SQL feels "simpler"** to AI models than learning ORM query syntax
- **ORM raw text methods** (like SQLAlchemy's `text()` with concatenation) hide SQLi
- **Dynamic filtering** forces AI to construct queries conditionally

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

## Secure Code Fix

### Fix 1: Parameterized Queries with sqlite3

```python
# ✅ SAFE — Parameterized queries
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",  # ? placeholder
        (user_id,)
    )
    return cursor.fetchone()
```

### Fix 2: SQLAlchemy with Proper Bind Parameters

```python
# ✅ SAFE — SQLAlchemy with bind parameters
from sqlalchemy import text

def search_products(term):
    # Use :param style binding with text()
    query = text("SELECT * FROM products WHERE name LIKE :term")
    result = db.session.execute(query, {"term": f"%{term}%"})
    return result.fetchall()
```

### Fix 3: SQLAlchemy ORM (Best Practice)

```python
# ✅ SAFE — Use ORM query API
from models import Product

def search_products(term):
    # ORM handles parameterization automatically
    return Product.query.filter(Product.name.contains(term)).all()
```

### Fix 4: Django ORM (Best Practice)

```python
# ✅ SAFE — Django ORM
from django.db import models

def get_orders(status):
    # ORM handles parameterization
    return Order.objects.filter(status=status)

# For complex queries, use parameterized raw()
def get_orders_raw(status):
    return Order.objects.raw("SELECT * FROM orders WHERE status = %s", [status])
```

### Fix 5: Safe Dynamic ORDER BY

```python
# ✅ SAFE — Whitelist column names
ALLOWED_COLUMNS = {'name', 'email', 'created_at', 'id'}
ALLOWED_ORDERS = {'ASC', 'DESC'}

def list_users(sort_column, sort_order):
    if sort_column not in ALLOWED_COLUMNS:
        sort_column = 'id'
    if sort_order.upper() not in ALLOWED_ORDERS:
        sort_order = 'ASC'
    
    # After validation, it's safe to use f-string for column name
    query = text(f"SELECT * FROM users ORDER BY {sort_column} {sort_order}")
    cursor.execute(query)
```

### Fix 6: Safe IN Clauses

```python
# ✅ SAFE — Parameterized IN clause
def get_users_by_ids(id_list):
    placeholders = ', '.join(['?' for _ in id_list])
    cursor.execute(
        f"SELECT * FROM users WHERE id IN ({placeholders})",
        id_list  # Each element is a parameter, not interpolated
    )
```

---

## Prevention Checklist

- [ ] NEVER use f-strings or `%` formatting for SQL queries with user data
- [ ] Use parameterized queries (`?`, `:name`, `%s`) for ALL SQL execution
- [ ] Use ORM query APIs instead of raw SQL whenever possible
- [ ] For SQLAlchemy: use `text()` with bind parameters, not f-strings
- [ ] For Django: use `filter()`, `.get()`, `.raw()` with `%s` parameters
- [ ] For dynamic column/table names: validate against a whitelist
- [ ] Enable SQLAlchemy's warning for unsafe strings (`pool_pre_ping=True`)
- [ ] Use query linting tools (sqlfluff, squawk) in CI
- [ ] Run automated SQLi scanning (sqlmap, SQLAlchemy security scanners)
- [ ] Apply least privilege to database users (no DROP/TRUNCATE for app user)
- [ ] Use database firewalls or WAF rules as secondary defense

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2022-28346** | Django — SQLi in `QuerySet.annotate()`/`aggregate()`/`extra()` via crafted column-alias `**kwargs` | Arbitrary SQL execution |
| **CVE-2022-34265** | Django — SQLi via untrusted `Trunc(kind)` / `Extract(lookup_name)` arguments | Arbitrary SQL execution |
| **CVE-2021-35042** | Django — SQLi via unsanitized `QuerySet.order_by()` input | Arbitrary SQL execution |
| **CVE-2020-7471** | Django — SQLi via a crafted `StringAgg(delimiter)` in `contrib.postgres` | Arbitrary SQL execution |
| **CVE-2024-53908** | Django — SQLi in the `HasKey(lhs, rhs)` JSON lookup on Oracle | Arbitrary SQL execution |

---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
f"SELECT ... WHERE id = {user_input}"       # 💥 Direct interpolation
f"SELECT ... WHERE name = '{user_input}'"    # 💥 String wrapping
f"INSERT INTO ... VALUES ({user_input})"     # 💥 Insert injection
cursor.execute(f"SELECT ...")                # 💥 F-string in execute
text(f"SELECT ...")                          # 💥 F-string in text()
db.session.execute(f"...")                   # 💥 F-string session execute
connection.execute(f"...")                   # 💥 F-string connection execute
```

> **Golden Rule:** If you see an f-string, `%s`, `.format()`, or `+` inside a SQL query string, it's SQL injection — even if it's wrapped in `text()` or `execute()`.
