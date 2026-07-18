---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
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