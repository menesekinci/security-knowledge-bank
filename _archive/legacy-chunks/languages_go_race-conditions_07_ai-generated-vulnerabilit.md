---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
category: "language-vuln"
language: "go"
chunk: 7
total_chunks: 12
heading: "AI-Generated Vulnerability: Channels + Shared State"
---

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