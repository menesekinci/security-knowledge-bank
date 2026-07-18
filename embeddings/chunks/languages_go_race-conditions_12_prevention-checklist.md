---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "Prevention Checklist"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 12/12
---

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