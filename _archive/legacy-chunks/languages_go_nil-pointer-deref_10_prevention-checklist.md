---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 10
total_chunks: 10
heading: "Prevention Checklist"
---

## Prevention Checklist

1. **Always check `error` returns** — The most common source of nil derefs in AI code.
2. **Use comma-ok pattern for type assertions** — `val, ok := x.(string)` — never bare `x.(string)`.
3. **Initialize maps with `make()`** — Never leave maps nil.
4. **Prefer value types over pointer types** — `User` vs `*User` when zero value is valid.
5. **Add nil receiver guards** — On exported methods that could be called on nil.
6. **Use `recover()` only at top-level goroutine boundaries** — Never inside business logic.
7. **Log stack traces on recovery** — `debug.Stack()` for diagnostics.
8. **Test with nil inputs** — Unit test functions that take pointers with explicit `nil`.