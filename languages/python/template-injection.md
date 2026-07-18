# Template Injection (SSTI) — Jinja2, Mako, Django

> **Severity:** Critical
> **CVSS:** 8.1–9.8 (High–Critical)
> **AI Generation Risk:** High — AI models extensively use Jinja2 and frequently render user input directly into templates

---

## Vulnerability Explanation

Server-Side Template Injection (SSTI) occurs when user input is embedded directly into a template engine's rendering pipeline without proper escaping. Template engines like Jinja2, Mako, and Django Templates offer powerful expression syntax that can invoke arbitrary Python code.

**The core problem:** When user input becomes part of the *template code* (not just the rendered output), the template engine parses and executes it. What looks like harmless text `{{ 7*7 }}` is evaluated as `49` — and `{{ config.__class__.__init__.__globals__['os'].popen('id') }}` executes shell commands.

### SSTI Severity by Engine

| Engine | Auto-Escaping | Sandbox | Commonly AI-Generated | Risk |
|---|---|---|---|---|
| Jinja2 | ✅ HTML auto-escape in Flask | Limited (can be escaped) | ✅ Very High | Critical |
| Mako | ❌ No auto-escaping by default | None | ✅ High | Critical |
| Django Templates | ✅ Auto-escape | Strong (limited syntax) | ✅ High | High |

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

## Prevention Checklist

- [ ] NEVER use `render_template_string()` or equivalent with user input in the template string
- [ ] Always use separate template files (`render_template()` in Flask, Django)
- [ ] Pass user input as template *variables*, never interpolated into template strings
- [ ] Enable HTML auto-escaping (default in Flask with `.jinja2` extension, Django default)
- [ ] Use `| e` or `| escape` Jinja2 filter for any variable that may contain HTML
- [ ] Avoid Mako templates in user-facing applications (no sandbox)
- [ ] Set `disable_execute=True` in Mako for untrusted templates
- [ ] Use `SandboxedEnvironment` in Jinja2 (defense in depth, not sole protection)
- [ ] Configure Content Security Policy (CSP) headers as secondary defense
- [ ] Audit all AI-generated code for `render_template_string(` calls
- [ ] Never allow user-controlled template file paths (`loader.get_source(user_input)`)
- [ ] Use `blinker` or similar to detect template rendering with user data

---

## Real-World CVEs

| CVE | CVSS | Description | Impact |
|---|---|---|---|
| **CVE-2025-23211** | 9.9 | Jinja2 SSTI in Tandoor Recipes (< 1.5.24) — any user can run commands | Recipe app — full system compromise |
| **CVE-2025-66434** | 8.8 | Frappe ERPNext (≤ 15.89.0) SSTI in `get_dunning_letter_text` via `frappe.render_template()` | Enterprise ERP — RCE / DB leak |
| **CVE-2024-32651** | 10.0 | changedetection.io (≤ 0.45.20) Jinja2 SSTI — unrestricted remote command execution | Web monitoring tool — full RCE |
| **CVE-2024-34359** | 9.6 | llama-cpp-python (0.2.30–0.2.71) renders a `.gguf` model's chat template in a sandbox-less `jinja2.Environment` | Malicious model file → RCE |
| **CVE-2024-56201** | 8.8 | Jinja compiler bug — an attacker controlling both template content and filename runs arbitrary Python even under the sandbox (fixed 3.1.5) | Jinja core — sandbox bypass to RCE |
| **CVE-2024-56326** | 7.8 | Jinja sandbox escape — an oversight in how `str.format` calls are detected lets template content execute arbitrary Python (fixed 3.1.5) | Jinja core — sandbox escape |

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
