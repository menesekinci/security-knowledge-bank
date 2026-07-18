# FastAPI Security Deep Dive

> **Category:** Python / FastAPI Security Knowledge Bank  
> **Focus:** OpenAPI exposure, auth bypass, Pydantic type confusion, CORS misconfig, file upload RCE  
> **Severity:** Critical  
> **CWE:** CWE-284 (Improper Access Control), CWE-20 (Improper Input Validation), CWE-287 (Improper Authentication), CWE-200 (Information Exposure), CWE-918 (SSRF), CWE-77 (Command Injection), CWE-434 (Unrestricted Upload), CWE-352 (CSRF), CWE-444 (HTTP Smuggling), CWE-22 (Path Traversal)  
> **AI Generation Risk:** Very High  
> **Last Updated:** July 2026

---

## Overview

FastAPI is the dominant Python framework for AI-generated APIs. Its automatic OpenAPI/Swagger generation, Pydantic-based validation, and async-first design make it the default choice for LLM-generated backend code. However, **these same features create unique security risks** that are amplified by AI coding assistants:

- **Automatic OpenAPI docs are publicly accessible by default** — exposing every endpoint, schema, and parameter
- **`debug=True` is on by default in AI-generated templates** — leaking stack traces and source code
- **CORS is frequently set to `allow_origins=["*"]`** — opening the API to any website
- **Pydantic type coercion** — AI-generated models may have dangerous type confusion
- **No built-in auth, rate limiting, or CSRF protection** — all must be added manually
- **Starlette underpinnings carry their own CVEs** — FastAPI inherits every Starlette vulnerability

This file documents FastAPI-specific security vulnerabilities, real CVEs across the FastAPI/Starlette/Uvicorn ecosystem, code patterns produced by AI coding assistants (vibe coding), and actionable fixes.

---

## 1. Vulnerability Explanation — FastAPI's Unique Attack Surface

### 1.1 Automatic OpenAPI/Swagger Exposure

FastAPI auto-generates OpenAPI documentation at `/docs` (Swagger UI) and `/redoc` (ReDoc) by default. In production, these endpoints reveal:

- Every API route, method, and parameter
- Request/response schemas (including sensitive fields)
- Authentication schemes and their implementation details
- Server information and version numbers

An attacker can discover your entire attack surface with a single `GET /docs` request.

### 1.2 Pydantic Schema Type Confusion (CWE-915)

Pydantic models have **lenient coercion by default** — a string `"123"` can be silently converted to an integer `123`. This allows:

- Bypassing input validation via type confusion
- Logic errors when values silently change type
- In strict mode disabled, AI-generated models may accept `null` for required fields

### 1.3 Starlette Host-Header Mismatch

The Starlette framework (FastAPI's ASGI base) rebuilds `request.url` from the `Host` header rather than using the raw ASGI `scope["path"]`. When the `Host` header contains special characters (`/`, `?`, `#`), the reconstructed URL path can differ from the actual routed path, allowing middleware and endpoint authorization checks based on `request.url` to be bypassed (see CVE-2026-48710).

### 1.4 AI-Generated Endpoints Without Guards

LLMs prompted with "Build a REST API with FastAPI" produce endpoints that commonly lack:
- Authentication / authorization
- Rate limiting
- Input validation beyond basic Pydantic types
- File size limits on uploads
- CSRF protection
- Security headers

---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

| Prompt | Generated Pattern | Vulnerability |
|--------|-------------------|---------------|
| "Build a REST API with FastAPI" | `app = FastAPI(debug=True)`, no auth, `CORSMiddleware(allow_origins=["*"])` | Debug mode in production, CORS wide open, no auth |
| "Add user authentication" | Hardcoded JWT secret, no refresh token rotation, no rate limiting on `/login` | JWT forgery, brute-force login |
| "File upload endpoint" | `UploadFile` with no size limit, no type check, original filename used | Path traversal, DoS, malware upload |
| "Database query endpoint" | Raw SQL with f-strings instead of ORM | SQL injection |
| "Admin dashboard" | No middleware, all endpoints public, Swagger enabled | Full API exposure |
| "Add CORS for frontend" | `allow_origins=["*"]`, `allow_credentials=True` | CSRF bypass when credentials allowed with wildcard |
| "Rate limiting" | Not generated at all | No rate limiting on any endpoint |

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

## 5. Real CVEs / Vulnerabilities

### CVE-2026-2977 — FastApiAdmin Unrestricted Upload (RCE via Scheduled Task API)

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (High) — NIST / 6.3 (Medium) — VulDB |
| **CWE** | CWE-284 (Improper Access Control), CWE-434 (Unrestricted Upload) |
| **Affected** | FastApiAdmin ≤ 2.2.0 |
| **Published** | 2026-02-23 |
| **Type** | Unrestricted File Upload → RCE |

**Description:** A security vulnerability in FastApiAdmin up to version 2.2.0 affects the `upload_controller` function in `/backend/app/api/v1/module_common/file/controller.py` (Scheduled Task API component). Manipulation of the upload functionality leads to unrestricted upload of files with dangerous types, allowing remote code execution. The exploit has been publicly disclosed.

**Impact:** An authenticated attacker (requires low-privilege access) can upload arbitrary files to the server, including Python scripts or shell scripts that get executed by the scheduled task system, leading to full server compromise.

**Fix:** Upgrade to FastApiAdmin > 2.2.0. Restrict upload paths, validate file types server-side, and never allow uploaded files to be executed as code.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-2977

---

### CVE-2026-2978 — FastApiAdmin Unrestricted Upload (Second Vector)

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (High) — NIST / 6.3 (Medium) — VulDB |
| **CWE** | CWE-284 (Improper Access Control), CWE-434 (Unrestricted Upload) |
| **Affected** | FastApiAdmin ≤ 2.2.0 |
| **Published** | 2026-02-23 |
| **Type** | Unrestricted File Upload → RCE |

**Description:** A second unrestricted upload vulnerability in FastApiAdmin ≤ 2.2.0, this time in the `upload_file_controller` function in `/backend/app/api/v1/module_system/params/controller.py` (Scheduled Task API). Like CVE-2026-2977, this allows remote code execution via crafted file uploads.

**Impact:** Same as CVE-2026-2977 — full server compromise via file upload RCE.

**Fix:** Upgrade to FastApiAdmin > 2.2.0. Implement file type validation, size limits, and path sanitization.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-2978

---

### CVE-2026-48710 — Starlette BADHOST: Host-Header Auth Bypass (CRITICAL for FastAPI)

| Field | Value |
|-------|-------|
| **CVSS** | 6.5 (Medium) — CNA / 7.0 (High) — X41 D-Sec |
| **CWE** | CWE-444 (HTTP Request Smuggling), CWE-1289 (Improper Validation) |
| **Affected** | Starlette < 1.0.1 (all FastAPI installations on Starlette ≤ 1.0.0) |
| **Published** | 2026-05-26 |
| **Type** | Authentication Bypass → Potential RCE |

**Description:** A critical vulnerability in Starlette's HTTP request handling. The `Host` request header was not validated before being used to reconstruct `request.url`. Because Starlette's routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header (containing `/`, `?`, or `#`) can make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) can be bypassed.

A single malformed character in the `Host` header lets an attacker slip past access controls. X41 D-Sec demonstrated changing a 403 Forbidden response to 200 OK by adding one character to the `Host` header.

**Downstream Impact:** This vulnerability affects:
- All FastAPI applications running on Starlette ≤ 1.0.0
- Model-serving tools (LiteLLM, vLLM, OpenRouter proxies)
- API gateways, eval frameworks, agent frameworks, and MCP servers built on FastAPI
- Directly-exposed ASGI servers (no compliant reverse proxy)

**Fix:** Upgrade to Starlette ≥ 1.0.1. Starlette 1.0.1 validates the `Host` header against RFC 9112 §3.2 / RFC 3986 §3.2.2 and falls back to `scope["server"]` for malformed values.

**Mitigation:** Deploy behind a compliant reverse proxy (nginx, Apache HTTPD, HAProxy) that rejects malformed `Host` headers before they reach the application.

> **⚠️ CRITICAL NOTE:** As of May 2026, this vulnerability has received widespread attention because it affects "most of the model-serving, gateway, proxy, eval, agent, and MCP-server infrastructure that has been stood up in the last two years" (Secwest advisory). The CSO Online article warns that AI tooling built on FastAPI is the primary attack surface.

**References:**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-48710
- GHSA: https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr
- X41 D-Sec: https://www.x41-dsec.de/lab/advisories/x41-2026-002-starlette
- OSTIF: https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette
- CSO Online: https://www.csoonline.com/article/4177711/fastapi-based-ai-tools-exposed-to-authentication-bypass-by-flaw-in-starlette-framework.html
- Test tool: https://badhost.org

---

### CVE-2026-48817 — Starlette HTTPEndpoint Unsafe Reflection

| Field | Value |
|-------|-------|
| **CVSS** | 5.3 (Medium) — GitHub |
| **CWE** | CWE-470 (Unsafe Reflection) |
| **Affected** | Starlette ≤ 1.0.1 |
| **Published** | 2026-06-17 |
| **Type** | Unsafe Reflection → Authorization Bypass |

**Description:** When dispatching a request, `HTTPEndpoint` selects the handler by lowercasing the HTTP method and using `getattr()` to look it up as an attribute — without restricting the lookup to a known set of HTTP verbs. When an `HTTPEndpoint` subclass is registered through `Route(...)` without an explicit `methods=` argument, every method reaches the endpoint. If a non-standard HTTP method whose lowercased name matches an attribute on the endpoint subclass reaches the endpoint, that attribute is invoked as if it were a request handler. An attacker can reach internal helper methods that were never meant to be HTTP handlers, bypassing authorization checks.

**Impact:** Authorization bypass for internal endpoint methods. Attackers can call private methods by sending unusual HTTP verbs.

**Fix:** Upgrade to Starlette ≥ 1.1.0.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-48817

---

### CVE-2025-62727 — Starlette FileResponse DoS via Range Header

| Field | Value |
|-------|-------|
| **CVSS** | 7.5 (High) — GitHub |
| **CWE** | CWE-407 (Inefficient Algorithmic Complexity) |
| **Affected** | Starlette 0.39.0 — 0.49.1 |
| **Published** | 2025-10-28 |
| **Type** | Denial of Service |

**Description:** An unauthenticated attacker can send a crafted HTTP `Range` header that triggers quadratic-time processing in Starlette's `FileResponse` range parsing/merging logic. This enables CPU exhaustion per request, causing denial of service for endpoints serving files (e.g., `StaticFiles` or any use of `FileResponse`).

**Impact:** CPU exhaustion DoS on endpoints serving static files or using `FileResponse`.

**Fix:** Upgrade to Starlette ≥ 0.49.1.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-62727

---

### CVE-2021-32677 — FastAPI CSRF via JSON Content-Type Bypass

| Field | Value |
|-------|-------|
| **CVSS** | 8.1 (High) — NIST |
| **CWE** | CWE-352 (Cross-Site Request Forgery) |
| **Affected** | FastAPI < 0.65.2 |
| **Published** | 2021-06-09 |
| **Type** | CSRF |

**Description:** FastAPI versions below 0.65.2 that used cookies for authentication in path operations receiving JSON payloads were vulnerable to CSRF. FastAPI would try to read the request payload as JSON even if the content-type header was `text/plain`. Since `text/plain` requests are exempt from CORS preflights (Simple requests), browsers would execute them with cookies included. The JSON content would be parsed and accepted by the FastAPI application.

**Impact:** Cookie-based authentication can be bypassed. An attacker hosting a malicious page can trigger authenticated state-changing operations on the victim's FastAPI application.

**Fix:** Upgrade to FastAPI ≥ 0.65.2. The fix requires `application/json` or compatible JSON media types for JSON body parsing.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-32677

---

### CVE-2026-24486 — Python-Multipart Path Traversal (Affects FastAPI File Uploads)

| Field | Value |
|-------|-------|
| **CVSS** | 7.5 (High) — NIST / 8.6 (High) — GitHub |
| **CWE** | CWE-22 (Path Traversal) |
| **Affected** | python-multipart < 0.0.22 |
| **Published** | 2026-01-26 |
| **Type** | Path Traversal → Arbitrary File Write |

**Description:** A path traversal vulnerability in python-multipart (the library FastAPI uses for parsing multipart form data, including file uploads) when using non-default configuration options `UPLOAD_DIR` and `UPLOAD_KEEP_FILENAME=True`. An attacker can write uploaded files to arbitrary locations on the filesystem by crafting a malicious filename containing `../` sequences.

**Impact:** Any FastAPI application using python-multipart's `UPLOAD_DIR` and `UPLOAD_KEEP_FILENAME=True` is vulnerable to arbitrary file write, potentially leading to RCE (e.g., overwriting application code or writing to cron directories).

**Fix:** Upgrade to python-multipart ≥ 0.0.22. Workaround: avoid using `UPLOAD_KEEP_FILENAME=True`.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-24486

---

### Ecosystem CVE Summary

| CVE | Component | Severity | Type | Fixed In |
|-----|-----------|----------|------|----------|
| CVE-2026-2977 | FastApiAdmin | 8.8 High | Unrestricted Upload → RCE | > 2.2.0 |
| CVE-2026-2978 | FastApiAdmin | 8.8 High | Unrestricted Upload → RCE | > 2.2.0 |
| CVE-2026-48710 | Starlette | 6.5 Medium* | Auth Bypass (BADHOST) | ≥ 1.0.1 |
| CVE-2026-48817 | Starlette | 5.3 Medium | Unsafe Reflection Auth Bypass | ≥ 1.1.0 |
| CVE-2025-62727 | Starlette | 7.5 High | DoS via Range Header | ≥ 0.49.1 |
| CVE-2021-32677 | FastAPI | 8.1 High | CSRF via JSON | ≥ 0.65.2 |
| CVE-2026-24486 | python-multipart | 7.5 High | Path Traversal | ≥ 0.0.22 |
| CVE-2021-29510 | Pydantic | 5.3 Medium | Infinity/NaN Validation Bypass | ≥ 1.8.2 |

*\* CVE-2026-48710 is rated 7.0 (High) by X41 D-Sec and Secwest, who note it materially understates the downstream impact on AI infrastructure.*

---

## 6. Prevention Checklist

- [ ] **Disable debug mode:** Set `debug=False` in production; never ship `debug=True`
- [ ] **Disable or protect OpenAPI docs:** Set `docs_url=None`, `redoc_url=None`, `openapi_url=None` in production, or protect behind authentication middleware
- [ ] **Configure CORS tightly:** Use explicit `allow_origins` list; never `["*"]` with `allow_credentials=True`
- [ ] **Use Pydantic strict mode:** `model_config = {"strict": True}` to prevent type confusion
- [ ] **Add authentication to all endpoints:** Use `Depends()` with a security scheme (OAuth2, Bearer, API key); don't rely on endpoint-level checks alone
- [ ] **Implement rate limiting:** Use SlowAPI or similar; especially on auth, registration, and resource-intensive endpoints
- [ ] **Validate file uploads:** Check file extension, MIME type, size (max limit), and use UUID-based filenames; never use user-supplied filenames
- [ ] **Run behind a reverse proxy:** Always deploy behind nginx, Apache, Traefik, or similar for Host header validation, SSL termination, DoS protection, and request filtering
- [ ] **Use parameterized queries / ORM:** Never use f-strings or string formatting with SQL; use SQLAlchemy ORM or parameterized queries
- [ ] **Add security headers:** Use middleware to set `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
- [ ] **Use environment variables for secrets:** Never hardcode JWT secrets, API keys, database passwords, or session secrets
- [ ] **Upgrade dependencies regularly:** Pin and update Starlette, pydantic, python-multipart, uvicorn, and all other dependencies; watch for FastAPI and Starlette security advisories
- [ ] **Add CSRF protection:** If using cookie-based auth, ensure CSRF protections are in place (FastAPI < 0.65.2 was vulnerable via JSON content-type)
- [ ] **Validate Host header:** On Starlette < 1.0.1, validate the `Host` header against allowed domains; better yet, upgrade to ≥ 1.0.1
- [ ] **Set reasonable session lifetimes:** Limit JWT token expiry (15-60 minutes for access tokens), implement refresh token rotation
- [ ] **Log security events:** Log auth failures, rate limit hits, validation errors, and file uploads for audit and incident response

---

## 7. Vibe-Coding Red Flags (FastAPI-Specific)

1. **`debug=True` in `FastAPI()`** — Always an accidental production deployment waiting to happen. AI templates default to this.
2. **`app = FastAPI()` with no auth middleware** — Every endpoint is public by default. AI rarely adds auth unless prompted.
3. **`allow_origins=["*"]`** — The single most common AI-generated CORS configuration. Combined with a public API, this invites cross-origin abuse.
4. **No `docs_url=None`** — AI leaves Swagger/ReDoc open in every generated scaffold. Attackers get a full API inventory for free.
5. **`file.filename` used directly in path operations** — Path traversal vulnerability 101. AI doesn't sanitize filenames.
6. **F-string SQL queries** — AI models trained on tutorials generate `f"SELECT * FROM {table} WHERE id = {id}"` constantly.
7. **Hardcoded JWT secret** — AI writes `SECRET_KEY = "my-secret"` in the source file, checked into git, visible to everyone.
8. **No file size limit on `UploadFile`** — AI doesn't add size validation, allowing DoS via large uploads.
9. **`CORSMiddleware` added but no auth** — Common AI pattern: "adds CORS to fix frontend errors" but doesn't add authentication.
10. **No `try/except` on `db_session`** — AI generators frequently omit error handling, leaking stack traces with database connection details.
11. **`SessionMiddleware(secret_key="hardcoded")`** — Hardcoded Starlette session key enables session forgery.
12. **No rate limiter on `/login` or `/register`** — AI generates auth endpoints but never adds brute-force protection.
13. **`allow_credentials=True` with `allow_origins=["*"]`** — An invalid but not rejected CORS configuration that makes CSRF trivial.
14. **Using `raise` without HTTPException** — AI generates bare `raise Exception()` which FastAPI catches as 500 Internal Server Error, potentially leaking information.

---

## 8. References

- FastAPI Security Docs: https://fastapi.tiangolo.com/tutorial/security/
- FastAPI Release Notes: https://fastapi.tiangolo.com/release-notes/
- Starlette Security Advisories: https://github.com/Kludex/starlette/security/advisories
- CVE-2026-2977 NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-2977
- CVE-2026-2978 NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-2978
- CVE-2026-48710 NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-48710
- CVE-2026-48817 NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-48817
- CVE-2025-62727 NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-62727
- CVE-2021-32677 NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-32677
- CVE-2026-24486 NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-24486
- CVE-2021-29510 NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-29510
- BADHOST Test Tool: https://badhost.org
- X41 D-Sec Starlette Advisory: https://www.x41-dsec.de/lab/advisories/x41-2026-002-starlette
- OSTIF Disclosure: https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette
- CSO Online — FastAPI-based AI Tools Auth Bypass: https://www.csoonline.com/article/4177711/fastapi-based-ai-tools-exposed-to-authentication-bypass-by-flaw-in-starlette-framework.html
- Secwest Starlette Advisory: https://www.secwest.net/starlette
- Security Knowledge Bank Index: index.md
