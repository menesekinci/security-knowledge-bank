---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "2. Throttling"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 4/12
---

## 2. Throttling

### No Rate Limiting by Default

**Vulnerable Code:**
```python
# settings.py — 💀 No throttling (DRF default)
REST_FRAMEWORK = {
    # DEFAULT_THROTTLE_CLASSES is empty by default
}
```

**Secure Code:**
```python
# settings.py — ✅ Comprehensive throttling configuration
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",       # Anonymous users
        "user": "1000/hour",      # Authenticated users
        "login": "5/minute",      # Login endpoint
        "register": "3/hour",     # Registration endpoint
        "upload": "10/minute",    # File uploads
    },
}
```

### Bypass via View-Level Override

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Custom view removes throttling
class BulkDeleteView(APIView):
    throttle_classes = []  # 💀 No throttling on expensive operation

    def post(self, request):
        # Mass delete — no rate limiting
        User.objects.all().delete()
        return Response({"status": "deleted"})
```

**Secure Code:**
```python
# ✅ SECURE — Set appropriate throttle rates per view
class BulkDeleteView(APIView):
    throttle_classes = [UserRateThrottle]
    throttle_scope = "bulk_operations"

    def post(self, request):
        # Add additional safety checks
        if not request.user.is_staff:
            raise PermissionDenied
        throttled_count = min(len(request.data.get("ids", [])), 100)
        User.objects.filter(id__in=request.data["ids"][:throttled_count]).delete()
        return Response({"status": "deleted", "count": throttled_count})
```

---