---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "4. Browsable API in Production"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 6/12
---

## 4. Browsable API in Production

### Disabling Browsable API

**Vulnerable Code:**
```python
# settings.py — 💀 Browsable API renderer enabled in production
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.BrowsableAPIRenderer",  # 💀 Exposes admin-style UI
        "rest_framework.renderers.JSONRenderer",
    ],
}
```

**Secure Code:**
```python
# settings.py — ✅ Conditional rendering based on environment
import os

if os.getenv("DJANGO_ENV") == "production":
    REST_FRAMEWORK = {
        "DEFAULT_RENDERER_CLASSES": [
            "rest_framework.renderers.JSONRenderer",  # ✅ Only JSON in production
        ],
        "DEFAULT_PARSER_CLASSES": [
            "rest_framework.parsers.JSONParser",
        ],
    }
else:
    REST_FRAMEWORK = {
        "DEFAULT_RENDERER_CLASSES": [
            "rest_framework.renderers.BrowsableAPIRenderer",
            "rest_framework.renderers.JSONRenderer",
        ],
    }
```

---