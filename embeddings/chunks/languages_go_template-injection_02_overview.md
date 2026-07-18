---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "Overview"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 2/10
---

## Overview

Go has two built-in template packages with very different security properties:

| Package | Use Case | Auto-Escaping | Injection Risk |
|---|---|---|---|
| `html/template` | HTML output | Context-aware escaping for HTML, JS, CSS, URLs | Low (safe defaults) |
| `text/template` | Text, config files, code generation | **No escaping** | Critical when used for HTML |

The danger is that AI models frequently:
1. Use `text/template` for HTML generation (wrong package)
2. Use `html/template` but disable auto-escaping with `template.HTML`
3. Expose template execution to user-controlled template content
4. Use `text/template` for generating config files read by other services