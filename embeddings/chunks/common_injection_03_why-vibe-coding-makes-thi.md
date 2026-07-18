---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 3/11
---

## Why Vibe Coding Makes This Worse

AI code generators excel at producing working code quickly — but they **default to the simplest path**, which is often string concatenation or template literals. Common AI-generated patterns that introduce injection:

- **String interpolation in SQL:** `SELECT * FROM users WHERE id = '${userId}'` (instead of parameterized queries)
- **`eval()` or `exec()` for flexibility:** AI may reach for dynamic execution to "solve" a problem generically
- **NoSQL queries with `$where`:** AI loves MongoDB's `$where` operator because it's flexible, but it enables JavaScript injection
- **ORM misuse:** AI generates code that builds HQL/JPQL via concatenation instead of parameterized criteria
- **Forgotten input validation:** AI focuses on the "happy path" and omits sanitization

> **💡 Key Insight:** AI models trained on public code have seen millions of *insecure* examples. Without explicit security prompting, they generate the most common pattern — which is often the most vulnerable one.

---