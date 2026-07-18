---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "6. Additional Security Headers"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 8/12
---

## 6. Additional Security Headers

**Secure Code:**
```python
# settings.py — ✅ Comprehensive security headers
SECURE_CONTENT_TYPE_NOSNIFF = True     # X-Content-Type-Options: nosniff
SECURE_BROWSER_XSS_FILTER = True        # X-XSS-Protection: 1; mode=block
X_FRAME_OPTIONS = "DENY"                # X-Frame-Options: DENY
SECURE_HSTS_SECONDS = 31536000          # HTTP Strict Transport Security (1 year)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True              # Redirect HTTP → HTTPS
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

---