---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "5. Middleware Ordering"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 7/12
---

## 5. Middleware Ordering

### Critical Middleware Order

Django's middleware is processed in order. Incorrect ordering can bypass security protections.

**Vulnerable Code:**
```python
# settings.py — 💀 Middleware order vulnerabilities
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",        # CSRF before auth
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.security.SecurityMiddleware",     # ❌ Security last!
    "django.middleware.common.CommonMiddleware",         # ❌ Common after security
]
# 💀 SecurityMiddleware should be first for headers to be set on all responses
```

**Secure Code:**
```python
# settings.py — ✅ Proper middleware ordering
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",          # First — security headers
    "django.contrib.sessions.middleware.SessionMiddleware",   # Session
    "django.middleware.common.CommonMiddleware",              # Common (includes Content-Length)
    "django.middleware.csrf.CsrfViewMiddleware",              # CSRF
    "django.contrib.auth.middleware.AuthenticationMiddleware", # Auth
    "django.contrib.messages.middleware.MessageMiddleware",   # Messages
    "django.middleware.clickjacking.XFrameOptionsMiddleware",  # Clickjacking protection
]
```

---