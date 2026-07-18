---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "8. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 8. Vibe-Coding Red Flags

- [ ] **Connection string in config files** — the `.env` file committed to GitHub with `DATABASE_URL=postgresql://user:pass@host/db`
- [ ] **`sslmode=disable` or `useSSL=false`** — any AI-generated code that disables encryption
- [ ] **`allowPublicKeyRetrieval=true`** — almost always a sign the AI was debugging a connection error and disabled security
- [ ] **`GRANT ALL PRIVILEGES`** — the model defaulting to superuser access
- [ ] **String formatting in SQL queries** — `f"SELECT ... WHERE x = '{input}'"` or `"SELECT ... WHERE x = " + input`
- [ ] **No `.env.example` with DB_HOST/DB_USER/DB_PASS** — hardcoded values are worse
- [ ] **Docker Compose without database password** — `POSTGRES_PASSWORD: postgres` or `MYSQL_ROOT_PASSWORD: root`
- [ ] **Exposed database ports** — `ports: - "5432:5432"` or `ports: - "3306:3306"` without any firewall
- [ ] **No health check or connection validation** — missing `SELECT 1` ping in connection pool config
- [ ] **Generic `mysql2` / `psycopg2` without SSL options** — AI assumes defaults are safe
- [ ] **Database migrated via `root`** — any AI-generated migration script using admin credentials
- [ ] **No connection timeout configuration** — AI leaves default (infinite) timeouts
- [ ] **Database user from `@'%'`** — MySQL user created with access from any host
- [ ] **`postgres.conf` or `my.cnf` with `listen_addresses = '*'`** — binds to all interfaces
- [ ] **Text-to-SQL libraries without input sanitization** — Vanna AI-style libraries that execute generated SQL without validation

---