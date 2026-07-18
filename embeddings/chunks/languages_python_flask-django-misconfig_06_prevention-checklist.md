---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
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