---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
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