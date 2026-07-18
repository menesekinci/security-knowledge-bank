---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "Detection"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 8/10
---

## Detection

```bash
# Detect text/template usage in web handlers
gosec -include G203 ./...  # G203: Use of unescaped data in templates

# Detect template.HTML, JS, URL, CSS
grep -rn 'template\.\(HTML\|JS\|URL\|CSS\)' ./

# Detect text/template import alongside web code
grep -rn '"text/template"' ./
```