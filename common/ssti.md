# Server-Side Template Injection (SSTI)

**CWE:** CWE-94 (Improper Control of Generation of Code — Code Injection)
**CWE Top 25 2024:** #11 (Code Injection — up 12 spots from #23)

---

## What Is SSTI?

Server-Side Template Injection occurs when an attacker injects malicious template directives into a template that is **evaluated server-side**. Template engines (Jinja2, Handlebars, Freemarker, Pug, Twig) evaluate expressions embedded in templates — if user input is placed into template content without proper escaping, the attacker can execute arbitrary code.

**The impact:** Remote Code Execution (RCE), sensitive data exposure, server-side file read, complete server takeover.

## Why Vibe Coding Makes This Worse

- **AI uses template engines generically:** AI may generate code that passes user input to `renderTemplateString(input)` instead of passing it as template variables
- **AI concatenates into templates:** `template = "<h1>Hello " + name + "</h1>"` then passes to engine
- **AI picks the wrong render method:** Uses `renders()` (which evaluates templates) instead of `render()` (which passes variables)
- **Python/Nunjucks mishandling:** AI doesn't distinguish between rendering a template file vs. rendering a template string from user input

## Vulnerable Code Examples

### Python (Jinja2) — Vulnerable

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'world')
    # 🔴 VULNERABLE: user input is part of the template, not a variable
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
# Attack: ?name={{config}} → dumps Flask app config with SECRET_KEY!
# Attack: ?name={{''.__class__.__mro__[2].__subclasses__()}} → list all classes
# Worse: ?name={% import os %}{{ os.popen('id').read() }}
```

### Node.js (Handlebars) — Vulnerable

```javascript
const handlebars = require('handlebars');

app.get('/profile', (req, res) => {
    const username = req.query.username;
    // 🔴 VULNERABLE: user input as template
    const template = handlebars.compile(`<h1>Welcome, ${username}!</h1>`);
    res.send(template({}));
});
```

### Java (Freemarker) — Vulnerable

```java
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    // 🔴 VULNERABLE: user input evaluated as template expression
    String template = "<h1>Hello ${" + name + "}!</h1>";
    Template t = new Template("greeting", new StringReader(template), cfg);
    Writer out = new StringWriter();
    t.process(null, out);
    return out.toString();
}
```

### PHP (Twig) — Vulnerable

```php
$twig = new \Twig\Environment($loader);

// 🔴 VULNERABLE: user input as template
$template = $twig->createTemplate("<h1>Hello {{ $_GET['name'] }}</h1>");
echo $template->render();
```

## Fixed Code Examples

### Python (Flask) — Fixed

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'world')
    # ✅ SAFE: user input is a VARIABLE, not part of template
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)
```

### Node.js (Handlebars) — Fixed

```javascript
const handlebars = require('handlebars');

app.get('/profile', (req, res) => {
    const username = req.query.username;
    // ✅ SAFE: template is static, user data is a variable
    const template = handlebars.compile('<h1>Welcome, {{username}}!</h1>');
    res.send(template({ username }));
});
```

### Java (Freemarker) — Fixed

```java
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    // ✅ SAFE: user input passed as data
    model.addAttribute("name", name);
    // Template file uses ${name}
    return "greeting";
}
```

---

## Template Engine Safety Comparison

| Engine | Variable Escaped by Default | `renderString` Equivalent | Risk Level |
|---|---|---|---|
| Jinja2 | ✅ Yes (autoescape on) | `render_template_string()` | ⚠️ If user data in template string |
| Django Templates | ✅ Yes (autoescape on) | N/A | ✅ Safe |
| Handlebars/Mustache | ✅ Yes | `Handlebars.compile()` | ⚠️ Only if user input in template |
| Pug | ✅ Yes | N/A | ✅ Safe |
| Freemarker | ✅ No (autoesc off) | `new Template(...)` | 🔴 High risk |
| Twig | ✅ Yes | `createTemplate()` | ⚠️ If user data in template |
| EJS | ❌ No | `<%=` escapes, `<%-` raw | 🔴 High risk |
| Nunjucks | ✅ Yes | `renderString()` | ⚠️ If user data in template |
| Velocity | ❌ No | `evaluate()` | 🔴 High risk |

---

## Prevention Checklist for AI Prompts

```
✅ SSTI PREVENTION:
- NEVER concatenate user input into template strings
- Always use template variables ({{ name }}) not user input in template code
- Enable auto-escaping in your template engine
- Use static template files, not dynamically constructed templates
- If you must render user content, use a restrictive sandbox
- Avoid template engines that support code execution in templates
- For Jinja2: use SandboxedEnvironment
- For Express: render() with .pug/.hbs files, not template strings from user input
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Spring Security OAuth SpEL injection | CVE-2016-4977 | RCE — `response_type` evaluated as a SpEL expression |
| VMware Workspace ONE Access (Freemarker) SSTI | CVE-2022-22954 | Unauthenticated RCE via server-side template injection (CVSS 9.8) |
| changedetection.io (Jinja2) SSTI | CVE-2024-32651 | Unauthenticated RCE via unsafe Jinja2 templates |
| Jinja sandbox escape (Pallets Jinja < 3.1.5) | CVE-2024-56326 | Sandbox bypass → arbitrary Python execution via `str.format` |

---

## References

- [OWASP SSTI](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)
- [PortSwigger SSTI Guide](https://portswigger.net/web-security/server-side-template-injection)
- [PortSwigger SSTI Cheat Sheet](https://portswigger.net/web-security/server-side-template-injection/cheat-sheet)
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
