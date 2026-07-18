---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist for AI Prompts

```
✅ RACE CONDITION PREVENTION:
- Use database transactions for multi-step operations
- Use atomic update operations (findOneAndUpdate, UPDATE ... WHERE condition)
- Use row-level locks (SELECT ... FOR UPDATE)
- Add unique constraints to prevent duplicate operations
- For file operations: open the file, then verify, not the reverse
- Use optimistic locking with version numbers (increment on update)
- Avoid shared mutable state in async code
- Use message queues for serializing access to critical resources
- Test concurrent access with stress testing tools
```

---