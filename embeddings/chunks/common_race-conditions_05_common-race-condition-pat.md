---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "Common Race Condition Patterns"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 5/8
---

## Common Race Condition Patterns

| Pattern | Danger | Fix |
|---|---|---|
| Check-then-act | Two requests pass the check before either acts | Atomic operations (CAS, findAndModify) |
| Lazy initialization | Two threads initialize singleton simultaneously | Double-checked locking, synchronized |
| Read-compare-write | Read value, compare, write new value | Optimistic locking with version numbers |
| File TOCTOU | Check file state, then use it | Open file first, then verify |
| Non-atomic increment | `counter += 1` is read-modify-write | `UPDATE ... SET counter = counter + 1` |
| Async race | Two promises both resolve to modify shared state | Mutex, queue, or atomic operations |

---