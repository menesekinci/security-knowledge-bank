---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

### 1. Flask + Jinja2 render_template_string() (Most Common)

```python
# 🚫 VULNERABLE — AI-generated Flask endpoint
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # AI directly interpolates user input into template string
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)  # 💥 SSTI
```

### 2. Mako Templates Without Auto-Escaping

```python
# 🚫 VULNERABLE — AI-generated Mako template
from mako.template import Template

def render_page(user_input):
    # AI embeds user input directly in template
    template = Template(f"""
        <div>
            ${user_input}  <!-- 💥 Mako evaluates arbitrary Python -->
        </div>
    """)
    return template.render()
```

### 3. Django Templates with User Input in Context

```python
# 🚫 VULNERABLE — AI-generated Django view
from django.shortcuts import render
from django.template import Template, Context

def search(request):
    query = request.GET.get('q', '')
    # AI passes user input into the template context unsafely
    template = Template("Results for: {{ query }}")
    context = Context({'query': query})
    return render(request, template.render(context))
```

### 4. Email Templates with User Data

```python
# 🚫 VULNERABLE — AI-generated email rendering
from jinja2 import Environment

env = Environment()
def send_welcome_email(username):
    # AI generates template with user data embedded
    template = env.from_string(f"Welcome {username}!")  # 💥
    return template.render()
```

### Why AI Does This

- **Flask + Jinja2 is the default AI stack:** AI coding assistants generate Flask apps with Jinja2 templates more than any other web framework
- **`render_template_string()` is common in tutorials:** Training data contains many examples of dynamic template rendering
- **String interpolation is natural:** AI models think in terms of string concatenation, not template engine restrictions
- **No context of "trust boundary":** AI doesn't distinguish between template code and template data

---