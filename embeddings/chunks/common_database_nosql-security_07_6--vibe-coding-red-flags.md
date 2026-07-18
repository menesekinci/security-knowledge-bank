---
source: "common/database/nosql-security.md"
title: "NoSQL Database Security for AI-Generated Applications"
heading: "6. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, incidents, injection, nosql, prevention, real, vulnerability]
chunk: 7/8
---

## 6. Vibe-Coding Red Flags

### MongoDB Red Flags
- [ ] `mongodb://localhost:27017/db` — no auth, no TLS, default port
- [ ] `MongoClient()` without any options — no auth, no TLS
- [ ] `useNewUrlParser: true` — old API surface from pre-4.0 tutorials
- [ ] `bindIp: 0.0.0.0` — the classic "works on my machine" deployment
- [ ] `db.collection.find({$where: 'this.x == ' + input})` — JavaScript injection
- [ ] No `authSource` in connection string — defaults to `admin`, but not explicit
- [ ] `docker run mongo` without `MONGO_INITDB_ROOT_USERNAME` / `MONGO_INITDB_ROOT_PASSWORD`
- [ ] Using `root` role for application user
- [ ] No TLS in connection string (`?tls=false` or missing `?tls=true`)
- [ ] Query objects built from `req.body` without validation

### Redis Red Flags
- [ ] `requirepass` missing from redis.conf
- [ ] `protected-mode no` — explicit disable of the default protection
- [ ] `redis-server` without any `.conf` file
- [ ] `ports: "6379:6379"` — exposed to all interfaces
- [ ] Running Redis as `root`
- [ ] Using `FLUSHALL` in application code (often in AI-generated cache invalidation)
- [ ] No `rename-command` for dangerous commands
- [ ] `redis.Redis(host='...')` without password parameter
- [ ] Using `EVAL` / `EVALSHA` with user-influenced input
- [ ] Docker `redis:latest` without version pinning
- [ ] No `cap_drop` or security options in Docker Compose

### Elasticsearch Red Flags
- [ ] `xpack.security.enabled: false` — disabling all security
- [ ] `http://localhost:9200` — plain HTTP, no TLS
- [ ] `Elasticsearch()` without auth parameters
- [ ] No `ca_certs` / `verify_certs` in client initialization
- [ ] Dynamic mapping enabled with user-facing write APIs
- [ ] `search_template` with user-supplied parameters
- [ ] `discovery.type: single-node` without security (for production)
- [ ] No `_source` exclusions — exposing internal fields
- [ ] Wildcard queries that can map-explode the index
- [ ] `dynamic: true` on production indices

### General NoSQL Red Flags
- [ ] Any database exposed via `0.0.0.0` binding
- [ ] No firewall between app server and database
- [ ] Same password for multiple databases
- [ ] No connection timeout configuration
- [ ] No query timeout configuration
- [ ] Docker Compose without a separate internal network (`--network internal-net`)
- [ ] Default admin credentials without password rotation
- [ ] No monitoring or alerting for database connections
- [ ] Dependencies with known CVEs (always check library versions)
- [ ] Text-to-NoSQL pipelines — AI generating NoSQL queries without sanitization

---