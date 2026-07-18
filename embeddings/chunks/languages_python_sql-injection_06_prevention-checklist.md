---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] NEVER use f-strings or `%` formatting for SQL queries with user data
- [ ] Use parameterized queries (`?`, `:name`, `%s`) for ALL SQL execution
- [ ] Use ORM query APIs instead of raw SQL whenever possible
- [ ] For SQLAlchemy: use `text()` with bind parameters, not f-strings
- [ ] For Django: use `filter()`, `.get()`, `.raw()` with `%s` parameters
- [ ] For dynamic column/table names: validate against a whitelist
- [ ] Enable SQLAlchemy's warning for unsafe strings (`pool_pre_ping=True`)
- [ ] Use query linting tools (sqlfluff, squawk) in CI
- [ ] Run automated SQLi scanning (sqlmap, SQLAlchemy security scanners)
- [ ] Apply least privilege to database users (no DROP/TRUNCATE for app user)
- [ ] Use database firewalls or WAF rules as secondary defense

---