---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
heading: "Detection Tools"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, panic, vulnerability]
chunk: 9/10
---

## Detection Tools

```bash
# Go vet catches some nil deref patterns
go vet ./...

# Staticcheck is more thorough
staticcheck -checks 'SA5011' ./...  # Nil pointer dereference checks

# gosec catches panic/recover misuse
gosec ./...
```