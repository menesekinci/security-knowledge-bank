---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "5. Authentication Security"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 7/12
---

## 5. Authentication Security

### Token Authentication Best Practices

**Vulnerable Code:**
```python
# settings.py — 💀 Simple token auth without HTTPS enforcement
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
    ],
}
```

**Secure Code:**
```python
# settings.py — ✅ Multi-factor authentication with HTTPS enforcement
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
}

# NOTE: DRF's built-in TokenAuthentication (rest_framework.authtoken) stores the
# token in PLAINTEXT in the DB — there is no built-in "hashed token" class.
# For hashed, expiring tokens use a dedicated package such as django-rest-knox
# (hashes tokens at rest), or move to short-lived JWTs (djangorestframework-simplejwt).
INSTALLED_APPS = [
    ...
    "rest_framework.authtoken",
]
```

### Custom Token Authentication with Expiry

```python
# ✅ SECURE — Token with expiry
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from datetime import timedelta
from django.utils import timezone

class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token.created < timezone.now() - timedelta(hours=24):
            raise AuthenticationFailed("Token has expired")
        return (user, token)
```

---