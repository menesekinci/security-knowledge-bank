---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: Never Use render_template_string() with User Input

```python
# ✅ SAFE — Use render_template with separate template files
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # Template in separate file — never constructed from user input
    return render_template('greet.html', name=name)

# templates/greet.html:
# <h1>Hello, {{ name }}!</h1>  ← name is data, not code
```

### Fix 2: Proper Escaping with render_template_string()

If you MUST use `render_template_string()`, pass user input as template variables:

```python
# ✅ SAFE — User input is a variable, not part of template code
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # Template is static string; user input is a variable
    template = "<h1>Hello, {{ name | e }}!</h1>"
    return render_template_string(template, name=name)
```

### Fix 3: Jinja2 Sandboxed Environment

```python
# ✅ HARDENED — Use Jinja2 sandbox
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
# Note: SandboxedEnvironment is NOT cryptographically secure.
# It can still be escaped by determined attackers.
template = env.from_string("Hello {{ name | e }}!")
result = template.render(name=user_input)
```

### Fix 4: Mako — Disable Execution

```python
# ✅ SAFER — Mako with restricted execution
from mako.template import Template

# Enable disable_execute to prevent arbitrary code execution
template = Template("<div>${user_input}</div>", disable_execute=True)
result = template.render(user_input="Safe text here")
```

### Fix 5: Django — Use Template Variables, Not Dynamic Templates

```python
# ✅ SAFE — Django template with proper context
from django.shortcuts import render

def search(request):
    query = request.GET.get('q', '')
    # Template is static; query is context data
    return render(request, 'search.html', {'query': query})

# templates/search.html:
# Results for: {{ query }}
```

---