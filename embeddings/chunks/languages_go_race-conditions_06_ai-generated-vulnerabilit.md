---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "AI-Generated Vulnerability: Forgotten Unlock"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 6/12
---

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