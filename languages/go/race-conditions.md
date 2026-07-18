# Race Conditions — Data Races, Sync Misuse, and Race Detector Limits

## The Go Concurrency Challenge

Go makes concurrent programming easy with goroutines and channels — perhaps too easy. The language's simplicity leads developers to write concurrent code without fully understanding synchronization, which is the **#1 source of subtle, production-only bugs** in Go applications. AI-generated code is especially prone to races because LLMs:

1. Add goroutines liberally without considering shared state
2. Use `sync.Mutex` incorrectly (copy by value, forget to unlock)
3. Assume `map` access is safe (it is not — concurrent map access panics)
4. Use `time.Sleep` as a synchronization mechanism (always wrong)

## Go Does NOT Prevent Data Races

Unlike Rust, Go has **no compile-time data race prevention**. If two goroutines access the same variable concurrently and at least one is a write, it's a data race — even with Go's memory model. The Go race detector (`-race`) finds these dynamically in tests, but it cannot prove their absence.

## AI-Generated Vulnerability: Concurrent Map Access

```go
// AI-GENERATED — concurrent map access causes panic
type Cache struct {
    items map[string]Item
}

func (c *Cache) Get(key string) (Item, bool) {
    // No lock! BUG: This races with Set
    v, ok := c.items[key]
    return v, ok
}

func (c *Cache) Set(key string, item Item) {
    c.items[key] = item // No lock! BUG: Concurrent write
}

// Concurrent access from multiple goroutines triggers:
// fatal error: concurrent map read and map write
```

**Secure Fix**: Protect with `sync.RWMutex`.
```go
type Cache struct {
    mu    sync.RWMutex
    items map[string]Item
}

func (c *Cache) Get(key string) (Item, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    v, ok := c.items[key]
    return v, ok
}

func (c *Cache) Set(key string, item Item) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = item
}

// Even better: use sync.Map for high-read, low-write patterns
```

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

## AI-Generated Vulnerability: Forgotten Unlock

```go
// AI-GENERATED — conditional return skips unlock
func (s *Server) Process(w http.ResponseWriter, r *http.Request) {
    s.mu.Lock()
    
    if s.closed {
        return // BUG: Never unlocks! Deadlocks all future requests
    }
    
    // Process request...
    s.mu.Unlock()
}
```

**Secure Fix**: Always use `defer` immediately after lock.
```go
func (s *Server) Process(w http.ResponseWriter, r *http.Request) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.closed {
        return // Defer handles unlock
    }
    // Process request...
}
```

## AI-Generated Vulnerability: Channels + Shared State

```go
// AI-GENERATED — subtle race between channel send and state read
type Worker struct {
    jobs    chan Job
    counter int
}

func (w *Worker) Start() {
    go func() {
        for job := range w.jobs {
            w.counter++ // RACE: main goroutine reads w.counter without lock!
            process(job)
        }
    }()
}

func (w *Worker) Stats() int {
    return w.counter // Reading while goroutine writes = data race
}
```

## AI-Generated Vulnerability: Using `time.Sleep` for Synchronization

```go
// AI-GENERATED — sleep-based synchronization (always wrong)
func main() {
    var result string
    
    go func() {
        result = expensiveComputation()
    }()
    
    time.Sleep(100 * time.Millisecond) // BUG: "Should be enough time"
    fmt.Println(result) // May read zero value (race!)
}
```

**Secure Fix**: Use channels or `sync.WaitGroup`.
```go
func main() {
    ch := make(chan string)
    
    go func() {
        ch <- expensiveComputation()
    }()
    
    result := <-ch // Block until computation finishes
    fmt.Println(result)
}
```

## The Race Detector's Limits

Go's race detector (`go test -race`) is excellent but has fundamental limits:

| What It Catches | What It Misses |
|---|---|
| Actual races in code paths tested | Races in untested code paths |
| Read-write and write-write races | Logical races (order violations) |
| Races on heap and stack | Races triggered only under specific load patterns |
| Races on maps, slices, channels | Races involving `unsafe.Pointer` tricks |

## Advanced: `sync.Map` Misuse

`sync.Map` is often recommended as a "concurrent map" but has specific usage constraints:

```go
// AI-GENERATED — sync.Map used as regular map
var m sync.Map

func main() {
    m.Store("key", "value")
    // AI often tries: m["key"] = "value" — won't compile
    // But worse: AI uses Load and Range without understanding they're snapshots
    
    m.Range(func(key, value interface{}) bool {
        // DON'T modify m inside Range!
        // DON'T assume this is the latest value — it's a point-in-time snapshot
        return true
    })
}
```

## Real CVEs

- **CVE-2025-47907 (database/sql, CVSS 7.0)**: A genuine **data race** (CWE-362) in the standard library. If a query's context is cancelled during a `Rows.Scan()` call while other queries run in parallel, the results can be overwritten with those of another query — so `Scan` returns another query's data or an error. A confidentiality/integrity issue, not just a crash. Fixed in Go 1.23.12 and 1.24.6.
- **CVE-2021-36221 (net/http/httputil, CVSS 5.9)**: A **race condition** in `ReverseProxy` could trigger a panic when a request is aborted with `ErrAbortHandler` while another request is being processed concurrently — an availability (DoS) impact on proxy servers. Fixed in Go 1.15.15 and 1.16.7.

## Prevention Checklist

1. **Always use `-race` flag** in tests and during development — never rely on `go test` alone.
2. **`defer` lock/unlock immediately** — Never `Lock()` at the top and `Unlock()` at the bottom without defer.
3. **Never copy `sync.Mutex`, `sync.RWMutex`, `sync.WaitGroup`, `sync.Once`** — Use pointer receivers.
4. **Never use `time.Sleep` for synchronization** — Use channels, `sync.WaitGroup`, or `sync.Cond`.
5. **Prefer channels over shared memory** — "Do not communicate by sharing memory; instead, share memory by communicating."
6. **Use `sync.Map` carefully** — Only for specific access patterns (load-heavy, write-once). Use regular maps + mutex for general cases.
7. **Run race detection in CI** — `go test -race ./...` should be part of every build.
8. **Consider using `goleak`** — Detects goroutine leaks that can mask race conditions.
9. **Add race detection to integration tests** — Races rarely trigger in unit tests.
10. **Review AI code that adds goroutines** — Every `go func()` needs synchronization analysis.
