---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
heading: "How AI Generates SSRF in Go"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [advanced, code, cves, go, language-vuln, overview, real, ssrf, vulnerable]
chunk: 3/8
---

## How AI Generates SSRF in Go

LLMs frequently generate code that:
1. Accepts a URL from user input and directly passes it to `http.Get()`
2. Uses `http.Client` without timeout or redirect limits
3. Fetches resources from user-supplied file paths or domain names
4. Disables certificate verification (`InsecureSkipVerify: true`)