---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "9. Common AI-Produced Misconfigurations"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 11/12
---

## 9. Common AI-Produced Misconfigurations

1. **`AllowAny` as default permissions** — Most common DRF security mistake
2. **No throttling configured** — Rate limiting left at defaults (none)
3. **`fields = "__all__"` in ModelSerializer** — Exposes all model fields
4. **Browsable API in production** — Leaving admin-style UI accessible
5. **`CORS_ALLOW_ALL_ORIGINS = True`** — Allow all CORS origins
6. **`get_object()` without permission checks** — Missing object-level authorization
7. **Detailed error messages** — Leaking user existence or failure details
8. **No pagination** — DoS vulnerability via large result sets
9. **Token auth without expiry** — Tokens that never expire
10. **`exclude` instead of `fields` in serializers** — Exposure risk on model changes

---