---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "4. Secure Code Fixes"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 6/10
---

## 4. Secure Code Fixes

### 4.1 Production Hardening — Debug & Swagger

```python
# ✅ SECURE — Production-ready FastAPI config
from fastapi import FastAPI
import os

app = FastAPI(
    debug=False,                    # ← Explicitly off
    docs_url=None,                  # ← Disable Swagger in production
    redoc_url=None,                 # ← Disable ReDoc in production
    openapi_url=None,               # ← Disable OpenAPI JSON endpoint
)

# Alternative: Protect docs behind auth middleware
# Or: Enable docs only when an env var is set
if os.getenv("ENABLE_DOCS", "").lower() == "true":
    app.docs_url = "/docs"
    app.redoc_url = "/redoc"
    app.openapi_url = "/openapi.json"
```

### 4.2 Proper CORS Configuration

```python
# ✅ SECURE — Restrictive CORS
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://myapp.com",
    "https://admin.myapp.com",
]

# NEVER use allow_origins=["*"] with allow_credentials=True
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
```

### 4.3 Stricter Pydantic Validation

```python
# ✅ SECURE — Pydantic strict mode to prevent type confusion
from pydantic import BaseModel, Field

class Order(BaseModel):
    model_config = {"strict": True}  # ← No lenient coercion
    
    amount: int = Field(gt=0, le=1000000)  # ← Range validation
    is_admin: bool
    status_code: int = Field(ge=100, le=599)

# Now {"amount": "99999"} → validation error (expects int, got str)
```

### 4.4 Secure File Upload

```python
# ✅ SECURE — Validated file upload
import os
import uuid
from pathlib import Path
from fastapi import FastAPI, UploadFile, HTTPException

ALLOWED_EXTENSIONS = {".jpg", ".png", ".pdf", ".csv"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = Path("/secure/uploads")

@app.post("/upload")
async def upload_file(file: UploadFile):
    # Validate file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type {ext} not allowed")
    
    # Validate file size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large")
    
    # Use safe, random filename — never user-supplied
    safe_filename = f"{uuid.uuid4()}{ext}"
    filepath = UPLOAD_DIR / safe_filename
    
    # Ensure path is within UPLOAD_DIR (defense in depth)
    filepath = filepath.resolve()
    if not str(filepath).startswith(str(UPLOAD_DIR.resolve())):
        raise HTTPException(400, "Invalid path")
    
    with open(filepath, "wb") as f:
        f.write(content)
    
    return {"filename": safe_filename}
```

### 4.5 Secure Session Middleware

```python
# ✅ SECURE — Session secret from environment
import os
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET_KEY"],  # ← From env, not code
    https_only=True,      # ← Require HTTPS
    max_age=3600,         # ← 1 hour session lifetime
    same_site="lax",      # ← CSRF protection
)
```

### 4.6 ORM-Based Database Access

```python
# ✅ SECURE — Use ORM instead of raw SQL
from sqlalchemy import select
from fastapi import FastAPI

@app.get("/users")
async def get_users(username: str):
    # Parameterized query via ORM — no injection
    stmt = select(User).where(User.username == username)
    result = await db_session.execute(stmt)
    return result.scalars().all()
```

### 4.7 Authentication Middleware

```python
# ✅ SECURE — Auth middleware with dependency injection
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security_scheme = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = credentials.credentials
    # Validate token against your auth system
    payload = decode_jwt(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return payload

@app.get("/users")
async def list_users(user=Depends(verify_token)):
    # Only authenticated users reach here
    return {"users": [...]}

@app.post("/admin/delete")
async def delete_user(user_id: int, user=Depends(verify_token)):
    # Check admin role from token
    if not user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    ...
```

### 4.8 Rate Limiting with SlowAPI

```python
# ✅ SECURE — Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

@app.get("/login")
@limiter.limit("5/minute")  # ← Strict limit on auth endpoint
async def login(request: Request, ...):
    ...
```

### 4.9 Security Headers

```python
# ✅ SECURE — Security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

### 4.10 SQL Injection Prevention (ORM)

```python
# ✅ SECURE — SQLAlchemy ORM with parameterized queries
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# ALWAYS use ORM or parameterized queries
engine = create_async_engine("sqlite+aiosqlite:///db.sqlite")

@app.get("/users")
async def get_users(username: str):
    async with AsyncSession(engine) as session:
        # Safe: parameterized query
        result = await session.execute(
            text("SELECT * FROM users WHERE username = :username"),
            {"username": username}
        )
        return result.all()
```

---