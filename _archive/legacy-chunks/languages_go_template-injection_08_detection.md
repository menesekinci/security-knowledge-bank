---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
category: "language-vuln"
language: "go"
chunk: 8
total_chunks: 10
heading: "Detection"
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