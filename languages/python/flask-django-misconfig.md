# Flask & Django Misconfigurations

> **Severity:** High (data breach, RCE, or full compromise)
> **CVSS:** 7.5–9.1
> **AI Generation Risk:** Very High — AI defaults to development configurations

---

## Vulnerability Explanation

AI code assistants overwhelmingly generate Flask and Django applications in their **development configuration** — because that's what appears in tutorials, blog posts, and documentation. These development defaults are **dangerous in production** and lead to data breaches, remote code execution, or complete system compromise.

### The Three Most Critical Misconfigurations

| Misconfiguration | Flask | Django | Impact |
|---|---|---|---|
| Debug mode enabled | `DEBUG=True` | `DEBUG=True` | RCE via debugger, source code exposure |
| Secret key hardcoded | `app.secret_key = 'dev'` | `SECRET_KEY = 'dev'` | Session forgery, CSRF bypass |
| CORS wide open | `CORS(app)` with no options | `django-cors-headers` default | Cross-origin data theft |

---

## How AI / Vibe Coding Generates This

### 1. DEBUG=True in Production (Most Critical)

```python
# 🚫 VULNERABLE — AI-generated Flask app
from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = True  # 💥 AI leaves debug mode on

# Flask debug mode:
# - Shows detailed tracebacks with source code
# - Provides interactive debugger console (Werkzeug)
# - The debugger console allows arbitrary code execution!
```

**The exploit:** When `DEBUG=True`, Flask's interactive debugger (`Werkzeug`) is accessible. An attacker can trigger an error and use the debugger console to execute arbitrary Python code.

```python
# 🚫 VULNERABLE — AI-generated Django app (settings.py)
DEBUG = True  # 💥 Left from cookiecutter or AI template
ALLOWED_HOSTS = ['*']  # 💥 Wildcard hosts
```

### 2. Hardcoded SECRET_KEY

```python
# 🚫 VULNERABLE — AI-generated Flask secret key
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'  # 💥 Hardcoded, predictable
```

```python
# 🚫 VULNERABLE — AI-generated Django secret key
# settings.py
SECRET_KEY = 'django-insecure-xxxxx'  # 💥 From cookiecutter or AI template
```

**Impact of exposed SECRET_KEY:**
- Flask session cookie forgery (flask-unsign can decode/forge)
- Django session manipulation
- CSRF token forgery
- Flashed message manipulation
- Any HMAC-based token forgery

```bash
# Attacker can decode and forge Flask session cookies
pip install flask-unsign
flask-unsign --decode --cookie 'eyJ...'
flask-unsign --sign --cookie "{'is_admin': True}" --secret 'dev'
```

### 3. CORS Misconfiguration

```python
# 🚫 VULNERABLE — AI-generated CORS
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 💥 Allows all origins by default!
```

```python
# 🚫 VULNERABLE — AI-generated Django CORS
INSTALLED_APPS = [
    'corsheaders',
]
CORS_ALLOW_ALL_ORIGINS = True  # 💥 Wildcard CORS
```

### 4. Development Server in Production

```python
# 🚫 VULNERABLE — AI-generated production entrypoint
from flask import Flask

app = Flask(__name__)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # 💥 Development server
    # Flask's dev server is single-threaded, not security-hardened
    # Should use gunicorn, uwsgi, or waitress in production
```

### 5. Template Auto-Escaping Disabled

```python
# 🚫 VULNERABLE — AI disabling auto-escape
from jinja2 import Environment

env = Environment(autoescape=False)  # 💥 XSS risk!
```

### 6. Django ALLOWED_HOSTS = ['*']

```python
# 🚫 VULNERABLE — AI-generated Django settings
ALLOWED_HOSTS = ['*']  # 💥 Host header injection
```

This enables:
- HTTP host header attacks
- Password reset poisoning
- Cache poisoning

---

## Vulnerable Code Examples

### Complete Vulnerable Flask App

```python
# 🚫 VULNERABLE — AI-generated Flask app (every line has issues)
from flask import Flask, session
from flask_cors import CORS
import os

app = Flask(__name__)
app.config['DEBUG'] = True          # 💥 Debug in production
app.config['SECRET_KEY'] = 'dev'    # 💥 Hardcoded secret
CORS(app)                           # 💥 Wildcard CORS

@app.route('/')
def index():
    session['user'] = 'admin'       # 💥 Session can be forged
    return 'Hello'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # 💥 Dev server
```

### Complete Vulnerable Django App

```python
# 🚫 VULNERABLE — AI-generated Django settings.py
DEBUG = True
SECRET_KEY = 'django-insecure-xxxxxxxxxxxx'  # From cookiecutter
ALLOWED_HOSTS = ['*']
CORS_ALLOW_ALL_ORIGINS = True
```

---

## Secure Code Fix

### Fix 1: Production Configuration — Flask

```python
# ✅ SAFE — Flask production config
import os
from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = False  # ✅ Explicitly off

# Secret key from environment — NEVER hardcoded
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("FLASK_SECRET_KEY environment variable not set!")

# Additional production settings
app.config['SESSION_COOKIE_SECURE'] = True       # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True     # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
```

### Fix 2: Production Configuration — Django

```python
# ✅ SAFE — Django production settings
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY must be set")

DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'True'

ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')

# Security middleware settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
```

### Fix 3: Restrictive CORS — Flask

```python
# ✅ SAFE — Restricted CORS
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=['https://app.example.com'], supports_credentials=True)
```

### Fix 4: Restrictive CORS — Django

```python
# ✅ SAFE — Django CORS
CORS_ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com',
]
CORS_ALLOW_CREDENTIALS = True
# CORS_ALLOW_ALL_ORIGINS = False  # Default is False, ensure it stays that way
```

### Fix 5: Use Production WSGI Server

```python
# ✅ SAFE — Production entrypoint
# Use gunicorn, waitress, or uvicorn instead of app.run()

# gunicorn entrypoint (from command line):
# gunicorn -w 4 -b 0.0.0.0:8000 app:app

# Or with waitress:
# from waitress import serve
# serve(app, host='0.0.0.0', port=8000)
```

### Fix 6: Environment-Specific Configs

```python
# ✅ SAFE — Split configurations
# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    # ... production settings

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    # ... dev settings

# app.py
app.config.from_object('config.ProductionConfig')
```

---

## Prevention Checklist

### Flask Checklist
- [ ] `DEBUG` is `False` in production — never `True`
- [ ] `SECRET_KEY` is from environment variable, never hardcoded
- [ ] `SESSION_COOKIE_SECURE` is `True` (HTTPS only)
- [ ] `SESSION_COOKIE_HTTPONLY` is `True`
- [ ] `SESSION_COOKIE_SAMESITE` is `'Lax'` or `'Strict'`
- [ ] CORS is configured with explicit origins, not wildcard
- [ ] Production uses gunicorn/uwsgi/waitress, not `app.run()`
- [ ] `TEMPLATES_AUTO_RELOAD` is `False` in production

### Django Checklist
- [ ] `DEBUG` is `False` in production
- [ ] `SECRET_KEY` is from environment variable
- [ ] `ALLOWED_HOSTS` is a specific list, not `['*']`
- [ ] `SECURE_SSL_REDIRECT` is `True`
- [ ] `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` are `True`
- [ ] `SECURE_HSTS_SECONDS` is set (>= 31536000)
- [ ] `X_FRAME_OPTIONS` is `'DENY'`
- [ ] `SECURE_CONTENT_TYPE_NOSNIFF` is `True`
- [ ] Database passwords from environment, not hardcoded

---

## Real-World CVEs

| CVE | Description | CVSS | Impact |
|---|---|---|---|
| **CVE-2023-30861** | Flask caches a response with `Set-Cookie` when the `session` is refreshed but not accessed, so `Vary: Cookie` is omitted — a caching proxy can then serve one client's `session` cookie to other clients (fixed 2.2.5 / 2.3.2) | 7.5 | Session cookie disclosure / hijack |
| **CVE-2024-6221** | flask-cors 4.0.1 sets `Access-Control-Allow-Private-Network: true` by default, exposing private-network resources to cross-origin requests (fixed 5.0.0) | 7.5 | CORS / private-network data exposure |
| **CVE-2019-19844** | Django password-reset account takeover — an email that is equal to a victim's after Unicode case-folding gets the victim's reset token (fixed 1.11.27 / 2.2.9 / 3.0.1) | 9.8 | Account takeover |
| **CVE-2022-36359** | Django Reflected File Download — the `Content-Disposition` filename of a `FileResponse` derived from user input (fixed 3.2.15 / 4.0.7) | 8.8 | Reflected file download |
| **CVE-2023-31047** | Django `forms.FileField` / `ImageField` validation bypassed when one form field uploads multiple files (fixed 3.2.19 / 4.1.9 / 4.2.1) | 9.8 | Upload validation bypass |

---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
DEBUG = True                       # 💥 Production debug mode
SECRET_KEY = 'dev'                 # 💥 Hardcoded
SECRET_KEY = 'something-secret'    # 💥 Hardcoded (any value)
CORS(app)  # no args               # 💥 Open CORS
ALLOWED_HOSTS = ['*']              # 💥 Wildcard hosts
app.run(host='0.0.0.0')           # 💥 Dev server
autoescape=False                   # 💥 XSS vector
CSRF_COOKIE_SECURE = False         # 💥 CSRF over HTTP
SESSION_COOKIE_SECURE = False      # 💥 Session over HTTP
```

> **Golden Rule:** Every AI-generated Flask/Django app should have its config reviewed for these 5 items before deployment: DEBUG, SECRET_KEY, CORS, ALLOWED_HOSTS, and cookie security settings.
