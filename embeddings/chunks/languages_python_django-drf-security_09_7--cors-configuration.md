---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "7. CORS Configuration"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 9/12
---

## 7. CORS Configuration

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Allow all origins
CORS_ALLOW_ALL_ORIGINS = True  # 💀 Any website can call your API
```

**Secure Code:**
```python
# ✅ SECURE — Restrict to known origins
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]

# ✅ Use regex for dynamic subdomains when needed
CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^https://[\w-]+\.example\.com$",
]
```

---