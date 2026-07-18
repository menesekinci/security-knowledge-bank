---
source: "common/database/nosql-security.md"
title: "NoSQL Database Security for AI-Generated Applications"
heading: "5. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, incidents, injection, nosql, prevention, real, vulnerability]
chunk: 6/8
---

## 5. Prevention Checklist

### MongoDB
- [ ] **Enable authentication** — `security.authorization: "enabled"` in mongod.conf
- [ ] **Create admin and application users** with separate roles and passwords
- [ ] **Use SCRAM-SHA-256** — the strongest supported authentication mechanism
- [ ] **Bind to private IP only** — never `0.0.0.0`
- [ ] **Enable TLS** — `net.tls.mode: requireTLS`
- [ ] **Use `$jsonSchema` validation** — enforce data types and prevent operator injection
- [ ] **Disable `$where`** if not required — or restrict its use via `security.javascriptEnabled: false`
- [ ] **Don't expose port 27017** — use firewall rules or security groups
- [ ] **Set connection pool limits** — `maxPoolSize: 10`
- [ ] **Configure audit logging** — `auditLog.destination: syslog`
- [ ] **Upgrade regularly** — subscribe to MongoDB security advisories
- [ ] **Sanitize all user input** — never pass raw JSON to MongoDB queries

### Redis
- [ ] **Set `requirepass`** — use a strong, unique password (stored in secrets manager)
- [ ] **Enable `protected-mode yes`** — prevents external access
- [ ] **Bind to `127.0.0.1`** — or a private IP, never `0.0.0.0`
- [ ] **Disable dangerous commands** — `rename-command FLUSHALL ""`, `rename-command CONFIG ""`, etc.
- [ ] **Use ACLs** (Redis 6+) — create application-specific users with minimal permissions
- [ ] **Disable Lua scripting** if not required — `rename-command EVAL ""`
- [ ] **Don't run as root** — use a dedicated `redis` user
- [ ] **Enable TLS** — `tls-port 6379`, `port 0` (disable plain TCP)
- [ ] **Set `maxclients`** — prevent connection exhaustion
- [ ] **Enable slow log** — detect abuse: `slowlog-log-slower-than 10000`
- [ ] **Use `cap_drop: ALL`** in Docker — drop all capabilities
- [ ] **Set `timeout 300`** — close idle connections

### Elasticsearch
- [ ] **Enable X-Pack Security** — `xpack.security.enabled: true`
- [ ] **Set passwords** for all built-in users (elastic, kibana, logstash, beats)
- [ ] **Enable TLS** for both HTTP and transport layers
- [ ] **Bind to private IP** — never expose `0.0.0.0:9200`
- [ ] **Disable dynamic scripting** — `script.allowed_types: none`
- [ ] **Use strict mapping** — `dynamic: false` or `dynamic: strict`
- [ ] **Set field limits** — `index.mapping.total_fields.limit: 1000`
- [ ] **Enable audit logging** — `xpack.security.audit.enabled: true`
- [ ] **Use API keys** — application-specific credentials instead of shared passwords
- [ ] **Restrict `read_pipeline` privilege** — prevent DoS via template abuse
- [ ] **Configure HTTPS** — never use plain HTTP for REST API
- [ ] **Apply index-level security** — prevent unauthorized cross-index access

---