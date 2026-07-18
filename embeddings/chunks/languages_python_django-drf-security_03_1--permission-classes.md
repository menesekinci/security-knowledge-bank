---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "1. Permission Classes"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 3/12
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