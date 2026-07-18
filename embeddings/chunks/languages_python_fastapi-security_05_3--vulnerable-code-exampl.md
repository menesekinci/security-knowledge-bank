---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 5/10
---

## 3. Vulnerable Code Examples

### 3.1 Debug Mode & Swagger Exposed in Production

```python
# 💀 VULNERABLE — AI-generated FastAPI scaffold
# debug=True leaks stack traces, Swagger exposes all endpoints
from fastapi import FastAPI

app = FastAPI(debug=True)  # ← NEVER use debug=True in production
# /docs and /redoc are PUBLIC by default
```

### 3.2 Wide-Open CORS

```python
# 💀 VULNERABLE — CORS unrestricted
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # ← Any website can make API calls
    allow_credentials=True,        # ← Credentials + wildcard = CSRF
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 3.3 Pydantic Type Confusion Leading to Logic Bypass

```python
# 💀 VULNERABLE — Pydantic lenient coercion
from pydantic import BaseModel

class Order(BaseModel):
    amount: int          # ← "99999" becomes 99999, "true" becomes error
    is_admin: bool       # ← "yes", "1", "true" all become True
    status_code: int     # ← 0, "", null silently converted

# Attacker sends: {"amount": "99999", "is_admin": "yes", "status_code": 0}
# Pydantic interprets this as valid input
```

### 3.4 Path Traversal via File Upload

```python
# 💀 VULNERABLE — File upload with no validation
from fastapi import FastAPI, UploadFile

@app.post("/upload")
async def upload_file(file: UploadFile):
    # Uses original filename directly — path traversal!
    with open(f"/uploads/{file.filename}", "wb") as f:
        content = await file.read()
        f.write(content)
    return {"filename": file.filename}

# Attacker sends: filename = "../../etc/crontab"
# File written to /etc/crontab
```

### 3.5 Starlette Session Secret Hardcoded

```python
# 💀 VULNERABLE — Hardcoded session secret
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key="super-secret-key-123"  # ← Hardcoded, exposed in source
    # If leaked, attacker can forge session cookies
)
```

### 3.6 SQL Injection via Raw Queries

```python
# 💀 VULNERABLE — AI loves f-strings with SQL
from fastapi import FastAPI
import sqlite3

@app.get("/users")
async def get_users(username: str):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # AI frequently generates f-string queries
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
```

### 3.7 No Authentication on Routes

```python
# 💀 VULNERABLE — Every endpoint is public
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")          # ← Public — anyone can list users
async def list_users():
    return {"users": [...]}

@app.post("/admin/delete")  # ← Public — anyone can delete
async def delete_user(user_id: int):
    # No auth check
    ...
```

### 3.8 JWT with Hardcoded Secret

```python
# 💀 VULNERABLE — AI-generated JWT auth
from datetime import datetime, timedelta
from jose import jwt

SECRET_KEY = "hardcoded-secret"  # ← Exposed in source code
ALGORITHM = "HS256"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)  # ← Very long expiry
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# No refresh token rotation, no token revocation
```

---