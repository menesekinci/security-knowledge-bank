---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
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