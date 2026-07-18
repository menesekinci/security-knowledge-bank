---
source: "languages/go/go-web-framework-security.md"
title: "Go Web Framework Security: Gin / Echo / Fiber"
heading: "Overview"
category: "language-vuln"
language: "go"
severity: "high"
tags: [comparison, cross-framework, echo, fiber, framework, go, language-vuln, overview]
chunk: 2/11
---

## Overview

Go's three dominant web frameworks — Gin, Echo, and Fiber — each have unique security characteristics and known CVEs. All three share common risks around request binding, middleware ordering, and CSRF protection. Go's standard library `net/http` is also reviewed for comparison.

---