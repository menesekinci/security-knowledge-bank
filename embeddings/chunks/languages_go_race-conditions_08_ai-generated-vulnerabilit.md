---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "AI-Generated Vulnerability: Using `time.Sleep` for Synchronization"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 8/12
---

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