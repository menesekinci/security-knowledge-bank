---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
category: "language-vuln"
language: "go"
chunk: 4
total_chunks: 12
heading: "AI-Generated Vulnerability: Concurrent Map Access"
---

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