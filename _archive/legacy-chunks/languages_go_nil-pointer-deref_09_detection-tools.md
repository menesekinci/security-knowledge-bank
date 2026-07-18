---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 9
total_chunks: 10
heading: "Detection Tools"
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