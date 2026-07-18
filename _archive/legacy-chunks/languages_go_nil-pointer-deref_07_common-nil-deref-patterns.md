---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 7
total_chunks: 10
heading: "Common Nil-Deref Patterns from AI"
---

## Common Nil-Deref Patterns from AI

| Pattern | AI Code | Risk |
|---|---|---|
| Unchecked method return | `result := doSomething()` | If `doSomething` returns `(*T, error)`, AI may discard the error |
| Nil slice append | `var s []string; s = append(s, "a")` | Actually safe! Nil slice append works in Go. But AI may add unnecessary nil checks |
| Type assertion without ok | `val := x.(string)` | Panics if `x` is not a string. Need `val, ok := x.(string)` |
| Nil channel send | `ch <- value` | **Blocks forever** if ch is nil (not a panic, but a goroutine leak) |
| Nil interface value | `var w io.Writer = nil; w.Write([]byte("hi"))` | Panics — nil interface value with concrete method call |