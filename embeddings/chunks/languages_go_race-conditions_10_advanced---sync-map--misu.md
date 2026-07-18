---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "Advanced: `sync.Map` Misuse"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 10/12
---

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