# Django Security Deep Dive

> **Category:** Python / Django Security Knowledge Bank  
> **Focus:** CSRF, XSS filters, SQL injection protection, session security, middleware ordering  
> **Last Updated:** July 2026

---

## Overview

Django provides extensive built-in security protections, but misconfiguration and misuse remain common. This file covers Django's security features, known CVEs, common AI-produced misconfigurations, and provides vulnerable/secure code patterns.

---

## 1. SQL Injection Protections

### Django's Built-in Protection

Django's ORM uses parameterized queries by default, making raw SQL injection unlikely when using the ORM correctly. However, vulnerabilities still arise through:
- `RawSQL()` / `extra()` / `annotate()` with string interpolation
- `FilteredRelation` column aliases via `annotate()` / `alias()` dict expansion (CVE-2025-57833)
- `filter()` / `exclude()` / `get()` / `Q()` with a crafted `_connector` dict argument (CVE-2025-64459)
- `connection.cursor()` with raw queries

### CVE-2025-64459 — SQL Injection via Crafted `_connector` Dict

**CVSS:** 9.1 (Critical)  
**Affected:** Django 4.2 < 4.2.26, 5.1 < 5.1.14, 5.2 < 5.2.8  
**Description:** `QuerySet.filter()`, `QuerySet.exclude()`, `QuerySet.get()`, and the `Q()` class are subject to SQL injection when a suitably crafted dictionary — using dictionary expansion — is passed as the `_connector` argument. Attackers who can control the keyword arguments can manipulate the WHERE clause.

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Django < 4.2.26 / 5.1.14 / 5.2.8
# A crafted dict expanded as **kwargs can reach the internal `_connector` argument.
malicious = {"_connector": "... attacker-controlled SQL ..."}
results = User.objects.filter(**malicious)   # 💀 or Q(**malicious), .exclude(**malicious), .get(**malicious)
```

**Secure Code:**
```python
# ✅ SECURE — Upgrade to patched version (Django 4.2.26+, 5.1.14+, 5.2.8+).
# Never expand an untrusted dict directly into filter()/exclude()/get()/Q().
# Build lookups from a validated allowlist of field names instead:
ALLOWED_FIELDS = {"email", "username", "is_active"}
safe = {k: v for k, v in user_input.items() if k in ALLOWED_FIELDS}
results = User.objects.filter(**safe)
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-64459

### CVE-2025-57833 — FilteredRelation SQL Injection

**CVSS:** 8.1 (High)  
**Affected:** Django 4.2 < 4.2.24, 5.1 < 5.1.12, 5.2 < 5.2.6  
**Description:** `FilteredRelation` is subject to SQL injection in column aliases when a suitably crafted dictionary — using dictionary expansion — is passed as the `**kwargs` to `QuerySet.annotate()` or `QuerySet.alias()`. The attacker-controlled alias name is interpolated into the SQL.

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Django < 4.2.24 / 5.1.12 / 5.2.6
from django.db.models import FilteredRelation

# Attacker controls the keyword-argument name (the column alias) via dict expansion.
untrusted = {request.GET["alias"]: FilteredRelation(
    "entries", condition=Q(entries__pub_date__gt=date)
)}
results = Blog.objects.annotate(**untrusted)   # 💀 alias name injected into SQL
```

**Secure Code:**
```python
# ✅ SECURE — Upgrade to patched version
# Django 5.2.6+ properly escapes column aliases in FilteredRelation
from django.db.models import FilteredRelation, Q

alias = request.GET.get("alias")
# Validate alias against allowlist
ALLOWED_ALIASES = ["recent", "popular", "featured"]
if alias not in ALLOWED_ALIASES:
    raise ValueError("Invalid alias")
results = Blog.objects.annotate(
    recent_entries=FilteredRelation(
        Entry.objects.filter(pub_date__gt=date),
        alias=alias
    )
)
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-57833

### Raw SQL — Developer-Introduced Vulnerability

**Vulnerable Code:**
```python
# 💀 VULNERABLE — String interpolation in raw SQL
def search_users(request):
    name = request.GET.get("name")
    results = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
    # 💀 SQL injection via name parameter
```

**Secure Code:**
```python
# ✅ SECURE — Use parameterized queries
def search_users(request):
    name = request.GET.get("name")
    results = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
    # OR use ORM:
    results = User.objects.filter(username=name)
```

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

## 3. Cross-Site Scripting (XSS) Protection

### Django's Auto-Escaping

Django templates auto-escape HTML by default. Common bypasses include:

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Using safe filter or mark_safe on user input
from django.utils.safestring import mark_safe

def render_comment(request):
    comment = request.GET.get("comment")
    # 💀 mark_safe bypasses auto-escaping
    return render(request, "comment.html", {"comment": mark_safe(comment)})
```

```html
{# comment.html — 💀 Template renders raw HTML #}
<div>{{ comment }}</div>
```

**Secure Code:**
```python
# ✅ SECURE — Let Django's template engine auto-escape
def render_comment(request):
    comment = request.GET.get("comment")
    return render(request, "comment.html", {"comment": comment})
```

```html
{# comment.html — ✅ Auto-escaped by Django #}
<div>{{ comment }}</div>
{# Use |safe ONLY on trusted content #}
<div>{{ trusted_html_content|safe }}</div>
```

### Common Pitfall — XSS via `format_html` Misuse (no CVE — code pattern)

**Vulnerable Code:**
```python
# 💀 VULNERABLE — pre-formatting the string defeats format_html's escaping
from django.utils.html import format_html

def user_greeting(request):
    name = request.GET.get("name")
    # 💀 f-string builds the HTML BEFORE format_html sees it, so `name`
    # is never escaped — format_html only escapes its {} arguments.
    return format_html(f"<h1>Welcome, {name}</h1>")
```

**Secure Code:**
```python
# ✅ SECURE — Use format_html correctly
from django.utils.html import format_html

def user_greeting(request):
    name = request.GET.get("name")
    # ✅ Pass user data as a {} argument — format_html escapes each argument.
    return format_html("<h1>Welcome, {}</h1>", name)
```

---

## 4. Session Security

### Common Session Misconfigurations

**Vulnerable Code:**
```python
# settings.py — 💀 Insecure session settings
SESSION_COOKIE_SECURE = False       # Sends cookie over HTTP
SESSION_COOKIE_HTTPONLY = False     # Accessible via JavaScript
SESSION_COOKIE_SAMESITE = None      # No SameSite protection
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Persistent sessions
SESSION_COOKIE_AGE = 1209600        # 2 weeks (default, too long)
```

**Secure Code:**
```python
# settings.py — ✅ Secure session configuration
SESSION_COOKIE_SECURE = True           # HTTPS only
SESSION_COOKIE_HTTPONLY = True         # Not accessible via JS
SESSION_COOKIE_SAMESITE = "Lax"        # SameSite=Lax
SESSION_EXPIRE_AT_BROWSER_CLOSE = True # Session ends on browser close
SESSION_COOKIE_AGE = 1800              # 30 minutes session timeout
SESSION_SAVE_EVERY_REQUEST = True      # Update session expiry on each request
```

### Session Serialization

**Vulnerable Code:**
```python
# settings.py — 💀 Pickle serializer (insecure)
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
# 💀 Pickle can execute arbitrary code if session data is tampered with
```

**Secure Code:**
```python
# settings.py — ✅ JSON serializer (default since Django 1.6)
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"
```

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

## 6. Additional Security Headers

**Secure Code:**
```python
# settings.py — ✅ Comprehensive security headers
SECURE_CONTENT_TYPE_NOSNIFF = True     # X-Content-Type-Options: nosniff
SECURE_BROWSER_XSS_FILTER = True        # X-XSS-Protection: 1; mode=block
X_FRAME_OPTIONS = "DENY"                # X-Frame-Options: DENY
SECURE_HSTS_SECONDS = 31536000          # HTTP Strict Transport Security (1 year)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True              # Redirect HTTP → HTTPS
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

---

## 7. CVE Roundup

| CVE | CVSS | Affected Versions | Type | Fixed In |
|-----|------|-------------------|------|----------|
| CVE-2025-64459 | 9.1 | < 4.2.26, < 5.1.14, < 5.2.8 | SQL Injection (`_connector` dict in filter/exclude/get/Q) | 4.2.26, 5.1.14, 5.2.8 |
| CVE-2025-57833 | 8.1 | < 4.2.24, < 5.1.12, < 5.2.6 | SQL Injection (FilteredRelation alias via annotate/alias) | 4.2.24, 5.1.12, 5.2.6 |
| CVE-2024-56374 | 7.5 | < 4.2.18, < 5.0.11, < 5.1.5 | DoS (IPv6 validation) | 4.2.18, 5.0.11, 5.1.5 |
| CVE-2024-45230 | 7.5 | < 4.2.16, < 5.0.9, < 5.1.1 | DoS (urlize / urlizetrunc) | 4.2.16, 5.0.9, 5.1.1 |
| CVE-2024-45231 | 5.3 | < 4.2.16, < 5.0.9, < 5.1.1 | User enumeration (PasswordResetForm) | 4.2.16, 5.0.9, 5.1.1 |
| CVE-2024-38875 | 7.5 | < 4.2.14, < 5.0.7 | DoS (urlize / urlizetrunc, brackets) | 4.2.14, 5.0.7 |

---

## 8. Version Recommendations

| Version | Status | Recommendation |
|---------|--------|---------------|
| Django 4.2 LTS | ✅ Supported until April 2026 | Minimum baseline |
| Django 5.1 | ⚠️ Latest stable | Recommended for new projects |
| Django 5.2 | 🚀 Latest | Use if available with security patches applied |

---

## 9. Common AI-Produced Misconfigurations

1. **`@csrf_exempt` on API views** — AI models often use `@csrf_exempt` without understanding CSRF implications
2. **`mark_safe(user_input)`** — Using `mark_safe` on untrusted HTML
3. **`RawSQL()` with f-strings** — String interpolation in raw SQL queries
4. **`DEBUG=True` in production** — Forgetting to set `DEBUG=False`
5. **Session serializer set to Pickle** — Defaulting to insecure serialization
6. **Wrong middleware order** — SecurityMiddleware not first
7. **`SECRET_KEY` hardcoded** — Embedding secret key in settings files
8. **`ALLOWED_HOSTS=['*']`** — Wildcard allowed hosts in production

---

## Verification / Source URLs

- Django Security Releases: https://www.djangoproject.com/weblog/2025/sep/03/security-releases/
- Django Security Documentation: https://docs.djangoproject.com/en/stable/topics/security/
- OWASP Django Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- Django Archive of Security Issues: https://docs.djangoproject.com/en/6.0/releases/security/
- NVD CVE-2025-64459: https://nvd.nist.gov/vuln/detail/CVE-2025-64459
- NVD CVE-2025-57833: https://nvd.nist.gov/vuln/detail/CVE-2025-57833
- NVD CVE-2024-56374: https://nvd.nist.gov/vuln/detail/CVE-2024-56374
