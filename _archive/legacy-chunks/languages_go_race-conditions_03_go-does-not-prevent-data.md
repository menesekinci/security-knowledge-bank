---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
category: "language-vuln"
language: "go"
chunk: 3
total_chunks: 12
heading: "Go Does NOT Prevent Data Races"
---

## Go Does NOT Prevent Data Races

Unlike Rust, Go has **no compile-time data race prevention**. If two goroutines access the same variable concurrently and at least one is a write, it's a data race — even with Go's memory model. The Go race detector (`-race`) finds these dynamically in tests, but it cannot prove their absence.