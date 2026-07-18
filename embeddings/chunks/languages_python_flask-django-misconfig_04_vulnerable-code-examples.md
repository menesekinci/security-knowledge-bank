---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "Vulnerable Code Examples"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
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