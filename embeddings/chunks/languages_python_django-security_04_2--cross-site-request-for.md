---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "2. Cross-Site Request Forgery (CSRF)"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 4/12
---

## 2. Cross-Site Request Forgery (CSRF)

### Django's CSRF Protection

Django includes `CsrfViewMiddleware` which generates and validates CSRF tokens. Common misconfigurations include:

### CVE-2016-7401 — Django CSRF Protection Bypass via Cookie Parsing

**CVSS:** 7.5 (High)  
**Affected:** Django < 1.8.15, 1.9.x < 1.9.10  
**Description:** On a site also running Google Analytics, Django's cookie-parsing code allowed a remote attacker to set arbitrary cookies and thereby bypass the intended CSRF protection mechanism. Fixed in 1.8.15 / 1.9.10.

The more common present-day cause of a CSRF bypass, though, is developer misuse — most often `@csrf_exempt` on a state-changing view:

**Vulnerable Code:**
```python
# 💀 VULNERABLE — CSRF exempt on sensitive views
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # 💀 Disables CSRF protection
def delete_account(request):
    account = request.user.account
    account.delete()
    return HttpResponse("Deleted")
```

**Secure Code:**
```python
# ✅ SECURE — Use csrf_protect instead, or require re-authentication
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def delete_account(request):
    # Require confirmation via POST with valid CSRF token
    account = request.user.account
    account.delete()
    return HttpResponse("Deleted")
```

### Common Misconfiguration: Missing CSRF Cookie Settings

**Vulnerable Code:**
```python
# settings.py — 💀 Missing CSRF cookie security settings
# CSRF_COOKIE_SECURE defaults to False
# CSRF_COOKIE_HTTPONLY defaults to False
```

**Secure Code:**
```python
# settings.py — ✅ Secure CSRF cookie configuration
CSRF_COOKIE_SECURE = True       # HTTPS only
CSRF_COOKIE_HTTPONLY = True     # Not accessible via JavaScript
CSRF_COOKIE_SAMESITE = "Lax"    # SameSite protection
CSRF_USE_SESSIONS = True        # Store CSRF token in session instead of cookie
```

---