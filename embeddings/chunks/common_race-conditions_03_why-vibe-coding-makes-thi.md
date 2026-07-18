---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI writes synchronous-looking async code:** `async/await` patterns that look correct but have hidden race windows
- **AI doesn't use transactions:** Generated code does separate read+write operations (check balance → deduct) without wrapping in a transaction
- **AI misses database-level locking:** `SELECT ... FOR UPDATE` is obscure and AI rarely generates it
- **AI uses "if exists then create" pattern:** Checking existence before inserting without unique constraints
- **AI generates file-based temp files:** Check if file exists → read file → another process modifies it in between