---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
category: "language-vuln"
language: "go"
chunk: 9
total_chunks: 10
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2023-24539 (html/template)**: A template directive injection vulnerability in Go's `html/template` standard library. Under certain conditions, user-controlled template data could bypass context-aware escaping and inject raw HTML/JavaScript.
- **CVE-2022-41717 (net/http)**: Not a template issue itself, but demonstrates how Go's HTTP server interacts dangerously with template rendering — a path traversal in `http.FileServer` could read arbitrary template files.
- **CVE-2023-39325 (golang.org/x/net/http2)**: While not template-specific, template rendering inside HTTP/2 streams with concurrent requests could race on shared template state.