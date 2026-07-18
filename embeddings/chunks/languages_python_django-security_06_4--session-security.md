---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "4. Session Security"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 6/12
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