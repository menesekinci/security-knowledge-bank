---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
heading: "AI-Generated Vulnerability: Nil Method Receiver"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, panic, vulnerability]
chunk: 5/10
---

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