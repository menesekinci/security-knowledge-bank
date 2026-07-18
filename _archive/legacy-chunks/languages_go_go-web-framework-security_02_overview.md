---
source: "languages/go/go-web-framework-security.md"
title: "Go Web Framework Security: Gin / Echo / Fiber"
category: "language-vuln"
language: "go"
chunk: 2
total_chunks: 11
heading: "Overview"
---

## Overview

Go's three dominant web frameworks — Gin, Echo, and Fiber — each have unique security characteristics and known CVEs. All three share common risks around request binding, middleware ordering, and CSRF protection. Go's standard library `net/http` is also reviewed for comparison.

---