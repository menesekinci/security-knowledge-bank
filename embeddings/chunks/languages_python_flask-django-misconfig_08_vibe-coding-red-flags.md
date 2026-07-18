---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
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