---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
heading: "Detection"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [advanced, code, cves, go, language-vuln, overview, real, ssrf, vulnerable]
chunk: 7/8
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