---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "9. Common AI-Produced Misconfigurations"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 11/12
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