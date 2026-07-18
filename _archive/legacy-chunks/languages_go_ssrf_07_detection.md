---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
category: "language-vuln"
language: "go"
chunk: 7
total_chunks: 8
heading: "Detection"
---

## Detection

```bash
# gosec catches InsecureSkipVerify (G402)
gosec -include G402 ./...

# Detect http.Get with user input:
grep -rn 'http\.\(Get\|Post\|Do\)' ./*.go

# Staticcheck catches some redirect issues
staticcheck -checks 'SA5000' ./...
```