---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "The Go Concurrency Challenge"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 2/12
---

## The Go Concurrency Challenge

Go makes concurrent programming easy with goroutines and channels — perhaps too easy. The language's simplicity leads developers to write concurrent code without fully understanding synchronization, which is the **#1 source of subtle, production-only bugs** in Go applications. AI-generated code is especially prone to races because LLMs:

1. Add goroutines liberally without considering shared state
2. Use `sync.Mutex` incorrectly (copy by value, forget to unlock)
3. Assume `map` access is safe (it is not — concurrent map access panics)
4. Use `time.Sleep` as a synchronization mechanism (always wrong)