---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
category: "language-vuln"
language: "go"
chunk: 5
total_chunks: 12
heading: "AI-Generated Vulnerability: Mutex Copy"
---

## AI-Generated Vulnerability: Mutex Copy

```go
// AI-GENERATED — Mutex is copied by value (loses lock state)
type Counter struct {
    mu    sync.Mutex
    value int
}

func (c Counter) Increment() { // BUG: Method has value receiver!
    c.mu.Lock()
    defer c.mu.Unlock()
    c.value++ // This increments a COPY of Counter
}
```

**Problems**:
1. `sync.Mutex` must not be copied after first use — value receiver copies the entire `Counter`.
2. `c.value++` increments the copy, not the original.
3. This is a Golang vet warning, but AI code often skips `go vet`.

**Secure Fix**: Use pointer receiver.
```go
func (c *Counter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.value++
}
```