---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "7. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 8/10
---

## 7. Prevention Checklist

- [ ] **Never hardcode credentials** — use environment variables, secrets managers, or vault services
- [ ] **Enforce SSL/TLS** — set `sslmode=verify-full` (PostgreSQL) or `useSSL=true&verifyServerCertificate=true` (MySQL)
- [ ] **Use dedicated application users** — never use `postgres` superuser or MySQL `root` for application connections
- [ ] **Apply least privilege** — grant only SELECT, INSERT, UPDATE, DELETE on specific tables; never grant DDL
- [ ] **Restrict network access** — bind to private IPs only, use security groups/firewall rules
- [ ] **Implement connection pooling** — use PgBouncer, HikariCP, or SQLAlchemy pool with size limits
- [ ] **Set statement timeouts** — prevent runaway queries: `statement_timeout=30s` (PostgreSQL), `max_execution_time=30000` (MySQL)
- [ ] **Use parameterized queries** — never use string formatting/f-strings for SQL — always use placeholders (`%s`, `?`, `:param`)
- [ ] **Run `mysql_secure_installation`** — mandatory for any MySQL deployment
- [ ] **Enable audit logging** — pgaudit for PostgreSQL, audit_log plugin for MySQL
- [ ] **Keep versions updated** — subscribe to PostgreSQL and MySQL security announcements
- [ ] **Scan dependencies** — check for known CVEs in database drivers (psycopg2, PyMySQL, mysql2, Npgsql, etc.)
- [ ] **Use password rotation** — rotate database passwords at least every 90 days
- [ ] **Set `idle_in_transaction_session_timeout`** — prevents abandoned transactions holding locks
- [ ] **Enable row-level security** — for multi-tenant applications

---