---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
category: "language-vuln"
language: "go"
chunk: 3
total_chunks: 8
heading: "How AI Generates SSRF in Go"
---

## How AI Generates SSRF in Go

LLMs frequently generate code that:
1. Accepts a URL from user input and directly passes it to `http.Get()`
2. Uses `http.Client` without timeout or redirect limits
3. Fetches resources from user-supplied file paths or domain names
4. Disables certificate verification (`InsecureSkipVerify: true`)