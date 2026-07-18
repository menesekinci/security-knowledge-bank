---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
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