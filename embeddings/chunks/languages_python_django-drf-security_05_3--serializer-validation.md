---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "3. Serializer Validation"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 5/12
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