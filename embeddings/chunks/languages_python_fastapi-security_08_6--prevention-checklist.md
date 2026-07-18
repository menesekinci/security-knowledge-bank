---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "6. Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 8/10
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