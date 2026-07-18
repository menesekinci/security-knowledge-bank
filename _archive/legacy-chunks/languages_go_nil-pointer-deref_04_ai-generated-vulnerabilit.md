---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 4
total_chunks: 10
heading: "AI-Generated Vulnerability: Nil Map Write"
---

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