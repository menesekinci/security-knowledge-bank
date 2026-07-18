---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "1. SQL Injection Protections"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 3/12
---

## 1. SQL Injection Protections

### Django's Built-in Protection

Django's ORM uses parameterized queries by default, making raw SQL injection unlikely when using the ORM correctly. However, vulnerabilities still arise through:
- `RawSQL()` / `extra()` / `annotate()` with string interpolation
- `FilteredRelation` column aliases via `annotate()` / `alias()` dict expansion (CVE-2025-57833)
- `filter()` / `exclude()` / `get()` / `Q()` with a crafted `_connector` dict argument (CVE-2025-64459)
- `connection.cursor()` with raw queries

### CVE-2025-64459 — SQL Injection via Crafted `_connector` Dict

**CVSS:** 9.1 (Critical)  
**Affected:** Django 4.2 < 4.2.26, 5.1 < 5.1.14, 5.2 < 5.2.8  
**Description:** `QuerySet.filter()`, `QuerySet.exclude()`, `QuerySet.get()`, and the `Q()` class are subject to SQL injection when a suitably crafted dictionary — using dictionary expansion — is passed as the `_connector` argument. Attackers who can control the keyword arguments can manipulate the WHERE clause.

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Django < 4.2.26 / 5.1.14 / 5.2.8
# A crafted dict expanded as **kwargs can reach the internal `_connector` argument.
malicious = {"_connector": "... attacker-controlled SQL ..."}
results = User.objects.filter(**malicious)   # 💀 or Q(**malicious), .exclude(**malicious), .get(**malicious)
```

**Secure Code:**
```python
# ✅ SECURE — Upgrade to patched version (Django 4.2.26+, 5.1.14+, 5.2.8+).
# Never expand an untrusted dict directly into filter()/exclude()/get()/Q().
# Build lookups from a validated allowlist of field names instead:
ALLOWED_FIELDS = {"email", "username", "is_active"}
safe = {k: v for k, v in user_input.items() if k in ALLOWED_FIELDS}
results = User.objects.filter(**safe)
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-64459

### CVE-2025-57833 — FilteredRelation SQL Injection

**CVSS:** 8.1 (High)  
**Affected:** Django 4.2 < 4.2.24, 5.1 < 5.1.12, 5.2 < 5.2.6  
**Description:** `FilteredRelation` is subject to SQL injection in column aliases when a suitably crafted dictionary — using dictionary expansion — is passed as the `**kwargs` to `QuerySet.annotate()` or `QuerySet.alias()`. The attacker-controlled alias name is interpolated into the SQL.

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Django < 4.2.24 / 5.1.12 / 5.2.6
from django.db.models import FilteredRelation

# Attacker controls the keyword-argument name (the column alias) via dict expansion.
untrusted = {request.GET["alias"]: FilteredRelation(
    "entries", condition=Q(entries__pub_date__gt=date)
)}
results = Blog.objects.annotate(**untrusted)   # 💀 alias name injected into SQL
```

**Secure Code:**
```python
# ✅ SECURE — Upgrade to patched version
# Django 5.2.6+ properly escapes column aliases in FilteredRelation
from django.db.models import FilteredRelation, Q

alias = request.GET.get("alias")
# Validate alias against allowlist
ALLOWED_ALIASES = ["recent", "popular", "featured"]
if alias not in ALLOWED_ALIASES:
    raise ValueError("Invalid alias")
results = Blog.objects.annotate(
    recent_entries=FilteredRelation(
        Entry.objects.filter(pub_date__gt=date),
        alias=alias
    )
)
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-57833

### Raw SQL — Developer-Introduced Vulnerability

**Vulnerable Code:**
```python
# 💀 VULNERABLE — String interpolation in raw SQL
def search_users(request):
    name = request.GET.get("name")
    results = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
    # 💀 SQL injection via name parameter
```

**Secure Code:**
```python
# ✅ SECURE — Use parameterized queries
def search_users(request):
    name = request.GET.get("name")
    results = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
    # OR use ORM:
    results = User.objects.filter(username=name)
```

---