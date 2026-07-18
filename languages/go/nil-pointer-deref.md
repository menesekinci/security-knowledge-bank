# Nil Pointer Dereference and Panic Recovery

## Overview

Go has pointers, but unlike C, nil pointer dereferences cause a **controlled panic** (not undefined behavior). The program crashes cleanly — which is better than memory corruption, but still a **denial of service** vulnerability. In production web servers, a nil pointer dereference can crash the entire process.

AI-generated Go code is especially prone to nil pointer bugs because:
1. LLMs forget to check error returns before using values
2. LLMs assume functions always return valid pointers
3. LLMs use `recover()` in incorrect patterns that mask bugs

## AI-Generated Vulnerability: Nil Dereference from Error

```go
// AI-GENERATED — no nil check after function call
func getUserEmail(db *sql.DB, userID string) string {
    var email string
    err := db.QueryRow("SELECT email FROM users WHERE id = ?", userID).Scan(&email)
    // AI ignores error!
    return email
}
```

**Problem**: If the user doesn't exist, `Scan` returns `sql.ErrNoRows` and **`email` is unchanged** (empty string). The function silently returns an empty email — no way for the caller to distinguish "not found" from "email is empty."

### Worse: Nil Pointer Returned from Function

```go
// AI-GENERATED — may return nil
type Session struct {
    UserID string
    Token  string
}

func GetSession(token string) *Session {
    // Returns nil if session not found!
    return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    session := GetSession(token)
    // PANIC: nil pointer dereference
    fmt.Fprintf(w, "Welcome %s", session.UserID)
}
```

**Secure Fix**:
```go
func GetSession(token string) (*Session, error) {
    // Return error instead of nil
    return nil, fmt.Errorf("session not found")
}

func handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    session, err := GetSession(token)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "Welcome %s", session.UserID)
}
```

## AI-Generated Vulnerability: Nil Map Write

```go
// AI-GENERATED — write to nil map
type Cache struct {
    data map[string]string
}

func (c *Cache) Set(key, value string) {
    c.data[key] = value // PANIC if data is nil!
}

func NewCache() *Cache {
    return &Cache{} // data map is nil!
}
```

**Secure Fix**:
```go
func NewCache() *Cache {
    return &Cache{
        data: make(map[string]string),
    }
}
```

## AI-Generated Vulnerability: Nil Method Receiver

```go
// AI-GENERATED — nil receiver panic
type Config struct {
    Timeout time.Duration
}

func (c *Config) GetTimeout() time.Duration {
    return c.Timeout // PANIC if c is nil
}

var globalConfig *Config // initialized elsewhere, but maybe nil

func requestHandler(w http.ResponseWriter, r *http.Request) {
    timeout := globalConfig.GetTimeout() // PANIC if not initialized!
}
```

**Secure Fix**: Defensive nil check on receivers.
```go
func (c *Config) GetTimeout() time.Duration {
    if c == nil {
        return defaultTimeout // Graceful fallback
    }
    return c.Timeout
}
```

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

## Common Nil-Deref Patterns from AI

| Pattern | AI Code | Risk |
|---|---|---|
| Unchecked method return | `result := doSomething()` | If `doSomething` returns `(*T, error)`, AI may discard the error |
| Nil slice append | `var s []string; s = append(s, "a")` | Actually safe! Nil slice append works in Go. But AI may add unnecessary nil checks |
| Type assertion without ok | `val := x.(string)` | Panics if `x` is not a string. Need `val, ok := x.(string)` |
| Nil channel send | `ch <- value` | **Blocks forever** if ch is nil (not a panic, but a goroutine leak) |
| Nil interface value | `var w io.Writer = nil; w.Write([]byte("hi"))` | Panics — nil interface value with concrete method call |

## Real CVEs

- **CVE-2020-29652 (golang.org/x/crypto/ssh, CVSS 7.5)**: A **nil pointer dereference** in the Go SSH server library let a remote, unauthenticated attacker crash any SSH server built on it — a pure availability (DoS) impact. Fixed in the commit series after `v0.0.0-20201203163018-be400aefbc4c`.
- **CVE-2026-39835 (golang.org/x/crypto/ssh, CVSS 5.3)**: SSH servers that use `CertChecker` as the public-key callback without setting `IsUserAuthority` or `IsHostAuthority` could be made to **panic (nil pointer dereference)** by a client that presents a certificate. `CertChecker` now returns an error instead of dereferencing the nil callback. Fixed in x/crypto 0.52.0.

Both are the classic AI pattern from this file: a value assumed to be non-nil (a callback, a checker field) is dereferenced on an untrusted-input path, turning a missing nil guard into a remote crash.

## Detection Tools

```bash
# Go vet catches some nil deref patterns
go vet ./...

# Staticcheck is more thorough
staticcheck -checks 'SA5011' ./...  # Nil pointer dereference checks

# gosec catches panic/recover misuse
gosec ./...
```

## Prevention Checklist

1. **Always check `error` returns** — The most common source of nil derefs in AI code.
2. **Use comma-ok pattern for type assertions** — `val, ok := x.(string)` — never bare `x.(string)`.
3. **Initialize maps with `make()`** — Never leave maps nil.
4. **Prefer value types over pointer types** — `User` vs `*User` when zero value is valid.
5. **Add nil receiver guards** — On exported methods that could be called on nil.
6. **Use `recover()` only at top-level goroutine boundaries** — Never inside business logic.
7. **Log stack traces on recovery** — `debug.Stack()` for diagnostics.
8. **Test with nil inputs** — Unit test functions that take pointers with explicit `nil`.
