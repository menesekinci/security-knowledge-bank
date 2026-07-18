---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "6. Pagination to Prevent DoS"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 8/12
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