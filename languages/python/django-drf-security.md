# Django REST Framework Security Deep Dive

> **Category:** Python / Django REST Framework Security Knowledge Bank  
> **Focus:** Permission classes, throttling, serializer validation, Browsable API in production  
> **Last Updated:** July 2026

---

## Overview

Django REST Framework (DRF) is widely used for building APIs with Django. Its default settings are intentionally permissive, requiring developers to explicitly configure security. Common AI-produced misconfigurations include leaving `AllowAny` as the default permission class and exposing the Browsable API in production.

---

## 1. Permission Classes

### Default Permission Misconfiguration

**Vulnerable Code:**
```python
# settings.py — 💀 AllowAny by default (DRF default!)
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",  # 💀 EVERYONE can access every view
    ],
}
```

**Secure Code:**
```python
# settings.py — ✅ Require authentication by default
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
}
```

### Vulnerable View-Level Permissions

**Vulnerable Code:**
```python
# views.py — 💀 No permission checks on sensitive views
from rest_framework import generics

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # 💀 No permission_classes defined — inherits default (AllowAny)
```

**Secure Code:**
```python
# views.py — ✅ Explicit permission checks + object-level authorization
from rest_framework import generics, permissions

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    def get_object(self):
        obj = super().get_object()
        self.check_object_permissions(self.request, obj)  # Check object-level
        return obj
```

### CVE Pattern: Object-Level Authorization Bypass

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Overriding get_object without permission check
class OrderDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # 💀 No check_object_permissions — any authenticated user can access any order
        return get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
```

**Secure Code:**
```python
# ✅ SECURE — Object-level permission check
from rest_framework import permissions

class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user

class OrderDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    def get_object(self):
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
        self.check_object_permissions(self.request, obj)  # ✅ Critical!
        return obj
```

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

## 3. Serializer Validation

### Mass Assignment via ModelSerializer

**Vulnerable Code:**
```python
# serializers.py — 💀 Using __all__ or exclude exposes all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"   # 💀 Exposes ALL model fields including is_staff, is_superuser
        # OR
        exclude = ["password"]  # 💀 Denylist approach — new fields added later are exposed
```

**Secure Code:**
```python
# serializers.py — ✅ Explicit allowlist of fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]
        read_only_fields = ["id"]

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "is_staff", "is_active", "date_joined"]
        read_only_fields = ["id", "date_joined"]
```

### Missing Field-Level Validation

**Vulnerable Code:**
```python
# serializers.py — 💀 No validation on user input
class CommentSerializer(serializers.Serializer):
    content = serializers.CharField()  # 💀 No max_length, no sanitization
    post_id = serializers.IntegerField()  # 💀 No existence check
```

**Secure Code:**
```python
# serializers.py — ✅ Comprehensive validation
from rest_framework import serializers
from django.core.validators import MinLengthValidator, MaxLengthValidator

class CommentSerializer(serializers.Serializer):
    content = serializers.CharField(
        min_length=1,
        max_length=1000,
        validators=[MinLengthValidator(1), MaxLengthValidator(1000)]
    )
    post_id = serializers.IntegerField()

    def validate_post_id(self, value):
        """Field-level validation"""
        if not Post.objects.filter(id=value).exists():
            raise serializers.ValidationError("Post does not exist")
        return value

    def validate_content(self, value):
        """Sanitize content"""
        from django.utils.html import strip_tags
        return strip_tags(value)  # Prevent XSS in content
```

### Data Leakage via Error Messages

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Error messages leak implementation details
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        try:
            user = User.objects.get(username=data["username"])  # 💀 Leaks "user exists"
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist")
        if not user.check_password(data["password"]):
            raise serializers.ValidationError("Wrong password")  # 💀 Leaks "password wrong"
        return data
```

**Secure Code:**
```python
# ✅ SECURE — Generic error messages
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(username=data["username"], password=data["password"])
        if user is None:
            raise serializers.ValidationError("Invalid credentials")  # ✅ Generic
        data["user"] = user
        return data
```

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

## 6. Pagination to Prevent DoS

**Vulnerable Code:**
```python
# settings.py — 💀 Pagination disabled by default
REST_FRAMEWORK = {
    # DEFAULT_PAGINATION_CLASS is None by default
}
```

**Secure Code:**
```python
# settings.py — ✅ Enable pagination with reasonable limits
REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    # NOTE: there is no "MAX_PAGE_SIZE" setting in REST_FRAMEWORK. The hard cap is
    # `max_page_size` on the pagination CLASS (see SecurePagination below), which
    # only takes effect together with `page_size_query_param`.
}

# Cap client-controllable page size with a custom pagination class:
class SecurePagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = "page_size"  # lets clients request a size...
    max_page_size = 100                  # ...but never above this hard limit
```

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

## 8. Version Recommendations

| Package | Version | Status |
|---------|---------|--------|
| Django REST Framework | 3.15.x | ✅ Latest stable |
| djangorestframework-simplejwt | 5.4.x | ✅ Recommended JWT auth |
| django-cors-headers | 4.6.x | ✅ Required for CORS |
| django-filter | 25.1 | ✅ Filter support |
| djangorestframework-api-key | 3.1.x | ✅ API key auth |

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

## Verification / Source URLs

- OWASP DRF Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html
- DRF Permissions Documentation: https://www.django-rest-framework.org/api-guide/permissions/
- DRF Throttling Documentation: https://www.django-rest-framework.org/api-guide/throttling/
- DRF Authentication Documentation: https://www.django-rest-framework.org/api-guide/authentication/
- DRF Release Notes: https://www.django-rest-framework.org/community/release-notes/
- Django Security Documentation: https://docs.djangoproject.com/en/stable/topics/security/
