---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated code, flag these immediately:

```python
render_template_string(f"{{ {user_input} }}")   # 💥 Classic SSTI
render_template_string("..." + user_input + "...")  # 💥 String concat SSTI
Template(f"${{{user_input}}}")                   # 💥 Mako SSTI
Template(f"<div>{user_input}</div>")             # 💥 Mako SSTI
env.from_string(user_input)                      # 💥 User-controlled template
```

> **Golden Rule:** User input should NEVER appear inside a template string — only as variables passed *to* the template renderer.