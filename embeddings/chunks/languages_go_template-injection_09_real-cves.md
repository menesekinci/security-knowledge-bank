---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "Real CVEs"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 9/10
---

## Real CVEs

- **CVE-2023-24539 (html/template, CVSS 7.3)**: Angle brackets (`<>`) were **not treated as dangerous inside CSS contexts**, so a template like `<style>{{.}}</style>` fed untrusted input could close the CSS context early and inject HTML — an escaping bypass in the auto-escaper itself. Fixed in Go 1.19.9 and 1.20.4.
- **CVE-2023-24540 (html/template, CVSS 9.8 Critical)**: **Not all valid JavaScript whitespace characters were recognized as whitespace**, so template actions in a JavaScript context surrounded by unusual whitespace were sanitized incorrectly, enabling code injection. Fixed in Go 1.19.9 and 1.20.4.
- **CVE-2023-29400 (html/template, CVSS 7.3)**: Actions in **unquoted HTML attributes** (`<a href={{.}}>`) given empty or crafted input could, due to HTML normalization, let an attacker **inject arbitrary attributes** into the tag. Fixed in Go 1.19.9 and 1.20.4.

All three are flaws in the context-aware escaper that this page holds up as the safe default — a reminder that `html/template` is strong but has itself needed escaping-bypass patches, so keep the Go toolchain current.