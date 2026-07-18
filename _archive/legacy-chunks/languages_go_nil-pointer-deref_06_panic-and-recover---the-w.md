---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 6
total_chunks: 10
heading: "Panic and Recover — The Wrong Way"
---

## Panic and Recover — The Wrong Way

Go's `recover()` is intended to catch unexpected panics, not normal error handling. AI code frequently misuses it:

```go
// AI-GENERATED — incorrect panic handling that swallows errors
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    defer func() {
        if err := recover(); err != nil {
            // This catches ALL panics, including nil pointer derefs
            // But also out-of-memory, stack overflow, etc.
            // And does nothing useful with the error
            log.Printf("recovered: %v", err)
        }
    }()

    processRequest(w, r) // If this panics, the handler recovers
    // But response was partially written! Client gets truncated response
}
```

**Problems**:
1. If `processRequest` wrote partial headers before panicking, the client receives a corrupt HTTP response.
2. `recover()` catches **all** panics, including `runtime.StackOverflow` and `runtime.OutOfMemory` — which should crash.
3. Recovered panics leave state inconsistent (mutexes locked, files open, connections dangling).

### Secure Recovery Pattern

```go
// Proper panic recovery — only at top-level request handler
func PanicRecoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                // Log stack trace for diagnostics
                stack := debug.Stack()
                log.Printf("PANIC: %v\n%s", err, stack)
                // Send clean 500 — nothing was written yet because we're at the top
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```