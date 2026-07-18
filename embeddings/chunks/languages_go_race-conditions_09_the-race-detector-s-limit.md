---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "The Race Detector's Limits"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 9/12
---

## The Race Detector's Limits

Go's race detector (`go test -race`) is excellent but has fundamental limits:

| What It Catches | What It Misses |
|---|---|
| Actual races in code paths tested | Races in untested code paths |
| Read-write and write-write races | Logical races (order violations) |
| Races on heap and stack | Races triggered only under specific load patterns |
| Races on maps, slices, channels | Races involving `unsafe.Pointer` tricks |