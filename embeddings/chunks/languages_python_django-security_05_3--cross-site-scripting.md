---
source: "languages/python/django-security.md"
title: "Django Security Deep Dive"
heading: "3. Cross-Site Scripting (XSS) Protection"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cross-site, injection, language-vuln, overview, python, request, scripting, security, session]
chunk: 5/12
---

## 3. Cross-Site Scripting (XSS) Protection

### Django's Auto-Escaping

Django templates auto-escape HTML by default. Common bypasses include:

**Vulnerable Code:**
```python
# 💀 VULNERABLE — Using safe filter or mark_safe on user input
from django.utils.safestring import mark_safe

def render_comment(request):
    comment = request.GET.get("comment")
    # 💀 mark_safe bypasses auto-escaping
    return render(request, "comment.html", {"comment": mark_safe(comment)})
```

```html
{# comment.html — 💀 Template renders raw HTML #}
<div>{{ comment }}</div>
```

**Secure Code:**
```python
# ✅ SECURE — Let Django's template engine auto-escape
def render_comment(request):
    comment = request.GET.get("comment")
    return render(request, "comment.html", {"comment": comment})
```

```html
{# comment.html — ✅ Auto-escaped by Django #}
<div>{{ comment }}</div>
{# Use |safe ONLY on trusted content #}
<div>{{ trusted_html_content|safe }}</div>
```

### Common Pitfall — XSS via `format_html` Misuse (no CVE — code pattern)

**Vulnerable Code:**
```python
# 💀 VULNERABLE — pre-formatting the string defeats format_html's escaping
from django.utils.html import format_html

def user_greeting(request):
    name = request.GET.get("name")
    # 💀 f-string builds the HTML BEFORE format_html sees it, so `name`
    # is never escaped — format_html only escapes its {} arguments.
    return format_html(f"<h1>Welcome, {name}</h1>")
```

**Secure Code:**
```python
# ✅ SECURE — Use format_html correctly
from django.utils.html import format_html

def user_greeting(request):
    name = request.GET.get("name")
    # ✅ Pass user data as a {} argument — format_html escapes each argument.
    return format_html("<h1>Welcome, {}</h1>", name)
```

---