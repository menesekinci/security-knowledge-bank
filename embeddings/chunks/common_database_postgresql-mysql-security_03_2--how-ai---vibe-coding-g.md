---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "2. How AI / Vibe Coding Generates These Vulnerabilities"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 3/10
---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

### Prompt Patterns That Trigger Insecure Code

| Risk Level | Prompt Pattern | Typical LLM Output |
|---|---|---|
| Critical | "Create a quick API with PostgreSQL backend" | Hardcoded connection string, no env vars |
| Critical | "Deploy my app with Docker Compose" | Default creds, exposed ports, no auth |
| High | "Connect to MySQL database in Python" | `useSSL=false`, `allowPublicKeyRetrieval=true` |
| High | "Write a search endpoint for my products" | Raw SQL `f"... WHERE name LIKE '%{query}%'"` |
| High | "Add a database user for my application" | GRANT ALL PRIVILEGES, superuser account |
| Medium | "Set up PostgreSQL for development" | `sslmode=disable`, trust auth in pg_hba.conf |
| Medium | "Fix my database connection error" | Disable SSL, relax auth requirements |

### Why LLMs Produce Insecure Database Code

- **Training data skew**: Tutorial code (dev environments) outweighs production security patterns
- **Convenience bias**: Models optimize for "code that works immediately" over "code that is secure"
- **Missing context**: LLMs don't see your network topology, compliance requirements, or threat model
- **Verbosity avoidance**: Secure patterns (connection pooling, env vars, SSL config) require more code
- **Outdated knowledge**: Many models were trained on patterns predating current best practices (e.g., prior to MySQL 8.0's caching_sha2_password default)

---