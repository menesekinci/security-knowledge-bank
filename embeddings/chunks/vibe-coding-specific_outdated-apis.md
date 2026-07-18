---
source: "vibe-coding-specific/outdated-apis.md"
title: "🟡 Outdated API Usage"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [does, example, highest, prevention, risk, vibe-coding, what]
---

# 🟡 Outdated API Usage

## What Is It?

AI models' training data is cut off at a certain date (knowledge cutoff).
They **don't know** APIs, framework versions, and security updates released **after** this date.
Result: They suggest deprecated/removed APIs, old security practices, and removed functions.

## How Does It Manifest in Vibe Coding?

```
Prompt: "Write an async HTTP client with Python 3.13"
AI (cutoff: 2024): "Use httpx, do it like this..."
         → If there are changes in httpx in Python 3.13, the AI doesn't know!

Or even worse:
Prompt: "Set up a Django 5.2 project"
AI: "Use url()" → url() was deprecated in Django 3.1! Not available in 5.2! 💀
```

## Highest Risk Areas

| Area | Risk | Because |
|------|------|---------|
| **Django/Flask/FastAPI** | Old route definitions | Frameworks change rapidly |
| **React/Next.js** | Old hook/API usage | Next.js App Router vs Pages Router |
| **Python 3.12+** | New syntax features | AI suggests old patterns |
| **Kubernetes** | Old API versions | v1beta1 → v1 migrations |
| **JWT libraries** | Old decode() APIs | `jwt.decode()` parameters changed |
| **TensorFlow/PyTorch** | Old layer/function names | APIs change frequently |

## Example

```python
# AI-written "Django 5.2" code:
from django.conf.urls import url  # NOT in Django 4.0+!

urlpatterns = [
    url(r'^login/$', login_view)  # 💀 url() deprecated in Django 3.1!
]

# Correct way in 2026:
from django.urls import path

urlpatterns = [
    path('login/', login_view),
]
```

## Prevention

### ✅ Statements to Add to Prompts
```
"When writing code:
1. Use the documentation for [Framework] version [X]
2. Don't use deprecated APIs
3. Make sure every function you use exists in the current version
4. If unsure, add a 'check the documentation' note"
```

### 🔧 Practical Measures
1. **Give the AI current documentation links**: Say "Use the API on this page"
2. **Include the framework version in the prompt**: "Django 5.2, Python 3.13"
3. **Type checking + lint**: mypy, pyright — catches non-existent APIs
4. **Track DeprecationWarnings**: Don't suppress warnings in tests
5. **Have the AI do web search**: Say "Look at the latest examples on GitHub"

## 🔗 Related Vulnerabilities
- [Fake Security Code](fake-security-code.md)
- [Overreliance](overreliance.md)

---

**Severity: 🟡 Medium** — Usually caught at compile-time but can also blow up in production.
