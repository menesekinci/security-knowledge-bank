---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 10/11
---

## Prevention Checklist for AI Prompts

When asking AI to generate database or shell-interacting code, include these instructions in your prompt:

```
✅ REQUIREMENTS FOR THIS CODE:
- Use parameterized queries / prepared statements for ALL database operations
- NEVER use string concatenation or template literals in SQL/NoSQL queries
- NEVER use $where in MongoDB queries
- Use execFile/spawn with argument arrays instead of exec() with shell:true
- Validate and sanitize ALL user input before processing
- Use an ORM with parameterized queries (SQLAlchemy, Prisma, TypeORM, Hibernate)
- Add input type validation (typeof checks, schema validation with Zod/Joi)
- Escape special characters for the specific interpreter being used
- Do NOT use eval(), new Function(), or setTimeout(string) for dynamic code
- Set Content-Security-Policy headers to mitigate XSS
```

### Quick Decision Tree

```
User input goes into a query/command?
├── SQL database → Use parameterized queries (?, $1, :name)
├── NoSQL query → Use typed objects, avoid $where
├── OS command → Pass arguments as array, no shell=True
├── LDAP filter → Escape special chars or use library
├── EL/OGNL → Never evaluate user input as expressions
└── HTML output → Context-aware encoding (see XSS guide)
```

---