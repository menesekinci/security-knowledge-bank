---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
f"SELECT ... WHERE id = {user_input}"       # 💥 Direct interpolation
f"SELECT ... WHERE name = '{user_input}'"    # 💥 String wrapping
f"INSERT INTO ... VALUES ({user_input})"     # 💥 Insert injection
cursor.execute(f"SELECT ...")                # 💥 F-string in execute
text(f"SELECT ...")                          # 💥 F-string in text()
db.session.execute(f"...")                   # 💥 F-string session execute
connection.execute(f"...")                   # 💥 F-string connection execute
```

> **Golden Rule:** If you see an f-string, `%s`, `.format()`, or `+` inside a SQL query string, it's SQL injection — even if it's wrapped in `text()` or `execute()`.