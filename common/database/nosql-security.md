# NoSQL Database Security for AI-Generated Applications

- **Severity:** Critical
- **CWE:** CWE-306 (Missing Authentication), CWE-1188 (Insecure Default), CWE-94 (Code Injection), CWE-862 (Missing Authorization), CWE-200 (Information Exposure)
- **AI Generation Risk:** Very High

---

## 1. Vulnerability Explanation

NoSQL databases (MongoDB, Redis, Elasticsearch) are particularly dangerous in AI-generated applications because their default configurations prioritize ease of use over security. LLMs trained on quick-start tutorials and dev guides propagate these defaults into production without the necessary hardening steps. The consequences have been catastrophic: millions of breached records, ransomware, and cryptojacking campaigns.

### MongoDB Security Failures

**Default Configuration is Open:**
MongoDB, in its default configuration (pre-4.0 era and still common in tutorials), binds to `0.0.0.0` and enables no authentication. AI models trained on older tutorials frequently:

- Skip `mongod --auth` entirely
- Forget to create admin users
- Use `bindIp: 0.0.0.0` for "easy access"
- Expose port 27017 directly to the internet
- Disable TLS (`--tlsMode=disabled` or absent)
- Enable the REST interface (`--rest`)

**The 2017 MongoDB Ransomware Crisis:**
In early 2017, over 33,000 MongoDB instances were hijacked in a massive ransomware campaign. Attackers scanned Shodan for exposed MongoDB servers, dumped databases, deleted collections, and demanded Bitcoin ransoms. Over 22,900 databases were affected in that initial wave alone (source: Dark Reading). The root cause: MongoDB's default configuration had no authentication enabled.

Despite MongoDB changing defaults in version 4.0 (2018), AI models continue to generate code based on pre-4.0 tutorials, and new deployments still appear on Shodan daily.

**What AI Models Get Wrong:**
- AI uses `new MongoClient('mongodb://host:27017')` without auth options
- AI deploys with `docker run mongo` no environment variables for auth
- AI creates users but grants `root` role on `admin` database
- AI enables auth in production "checklist" but not in the actual connection code
- AI uses old `MongoClient` constructor without `authSource`

### Redis Security Failures

**No Authentication by Default:**
Redis has no authentication (`requirepass`) enabled by default. The `protected-mode` feature was added in Redis 3.2 (2016) but is trivially bypassed and many AI tutorials disable it explicitly or simply never mention it.

**AI-Generated Redis Issues:**

**Running as Root:** AI Docker configurations run Redis as root, enabling full filesystem access if exploited.

**Dangerous Commands Available (no rename):**
- `FLUSHALL` / `FLUSHDB` — immediately destroys all data
- `CONFIG SET` — changes runtime configuration
- `DEBUG SEGFAULT` — crashes the server
- `EVAL` — executes Lua scripts (source of multiple CVEs)
- `SLAVEOF` — turns the instance into a replication slave

**Exposed to Internet:** AI-generated `docker-compose.yml` often exposes Redis port 6379 with no firewall or password.

**Persistence and Backup Risks:**
AI-generated Redis configuration often uses `save ""` (no persistence) for simplicity, or uses `appendonly yes` without understanding the integrity implications.

**Cryptocurrency Mining Campaigns:**
Attackers routinely scan for Redis instances without authentication and inject cron jobs or SSH keys to install cryptocurrency miners. These campaigns persist because AI-generated applications continue to deploy Redis without: (1) `requirepass`, (2) `rename-command FLUSHALL ""`, (3) `bind` to private IP only.

### Elasticsearch Security Failures

**No Authentication / X-Pack Disabled:**
Elasticsearch prior to the Elastic Stack security features required X-Pack (now bundled but not enabled by default in open-source distributions). AI-generated Elasticsearch configurations:

- Use `xpack.security.enabled: false` (or omit it entirely)
- Expose port 9200 (REST API) to the internet
- Disable TLS on transport and HTTP layers
- Use dynamic mapping without schema validation
- Enable dynamic scripting (`script.allowed_types: inline`)

**Dynamic Mapping Injection:**
When Elasticsearch has dynamic mapping enabled, attackers can send requests that create new fields and mappings, potentially causing:
- Mapping explosions (thousands of fields causing cluster instability)
- Schema poisoning (indexing unexpected data types)
- Cluster-wide crashes (via "field explosion" attacks)

**Massive Data Exposure Incidents:**
- **Mother of All Breaches (MOAB, January 2024):** An unsecured Elasticsearch cluster containing 26 billion records (12 TB) of aggregated breach data was discovered, comprising data from countless breaches across hundreds of sources (SpyCloud).
- **Elasticsearch data leaks are a recurring pattern** — in 2024, researchers continued finding exposed clusters containing hundreds of millions of records, often with default or no authentication.

---

## 2. NoSQL Injection Specific

### MongoDB `$where` Injection

MongoDB's `$where` operator passes a JavaScript string to be evaluated on the database server. AI-generated code often uses `$where` to perform "flexible" queries:

```javascript
// VULNERABLE - AI-generated $where injection
app.post('/search', (req, res) => {
  const username = req.body.username;
  db.collection('users').find({
    $where: `this.username == '${username}'`  // JavaScript injection!
  }).toArray((err, docs) => res.json(docs));
});
```

**Attack:**
```json
{"username": "' || true || '"}
```
Returns all users. An attacker can escalate to `' || sleep(5000) || '` for blind injection or `' || (function(){...})() || '` for arbitrary JavaScript execution.

### MongoDB `$gt` / `$ne` / `$regex` Bypass

Even without `$where`, MongoDB queries are vulnerable to operator injection when user input is passed directly:

```javascript
// VULNERABLE - AI-generated direct object injection
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.collection('users').findOne({
    username: username,   // Could be {"$gt": ""} or {"$ne": null}
    password: password    // Could be {"$gt": ""}
  }).then(user => { /* authentication bypassed */ });
});
```

**Attack:**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
Logs in as the first user in the database — typically an admin.

### Elasticsearch Query DSL Injection

When user input is embedded in Elasticsearch query JSON:

```python
# VULNERABLE - AI-generated Elasticsearch query injection
@app.route('/search')
def search():
    q = request.args.get('q')
    body = {
        "query": {
            "query_string": {
                "query": q  # No sanitization!
            }
        }
    }
    return es.search(index="products", body=body)
```

**Attack:**
```
/search?q=malicious+field"+]},"match_all":{}}
```

An attacker can manipulate the query structure, bypass filters, access restricted fields, or cause denial of service via expensive queries.

### Elasticsearch Script Injection

When dynamic scripts are enabled:

```json
// Attack payload sent to _update endpoint
{
  "script": {
    "source": "ctx._source.amount = -1; ctx.op = 'none'",
    "lang": "painless"
  },
  "query": {
    "match": {
      "user": "victim"
    }
  }
}
```

---

## 3. Vulnerable Code + Secure Fix per Database

### MongoDB: Vulnerable Code

```javascript
// VULNERABLE - AI-generated MongoDB connection
const MongoClient = require('mongodb').MongoClient;
const uri = "mongodb://localhost:27017/mydb";  // No auth, no TLS
MongoClient.connect(uri, (err, client) => {
  // Application logic
});
```

```python
# VULNERABLE - AI-generated Python MongoDB
from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")  # No auth, no TLS
db = client.mydb
```

### MongoDB: Secure Fix

```javascript
// SECURE - MongoDB with auth and TLS
const MongoClient = require('mongodb').MongoClient;
const uri = "mongodb://" +
    encodeURIComponent(process.env.MONGO_USER) + ":" +
    encodeURIComponent(process.env.MONGO_PASS) +
    "@" + process.env.MONGO_HOST + ":27017/mydb?" +
    "authSource=admin&" +
    "tls=true&" +
    "tlsCAFile=/etc/ssl/certs/ca.pem&" +
    "replicaSet=rs0&" +
    "retryWrites=true&" +
    "w=majority&" +
    "connectTimeoutMS=5000";

const client = new MongoClient(uri, {
    maxPoolSize: 10,
    minPoolSize: 2
});
```

```python
# SECURE - Python MongoDB with auth and TLS
from pymongo import MongoClient
import os

uri = "mongodb://" + os.environ['MONGO_USER'] + ":" + \
      os.environ['MONGO_PASS'] + "@" + os.environ['MONGO_HOST'] + \
      ":27017/mydb?authSource=admin&tls=true&tlsCAFile=/etc/ssl/certs/ca.pem"

client = MongoClient(uri, maxPoolSize=10)
```

### MongoDB: NoSQL Injection Protection

```javascript
// SECURE - Use strict schema validation and sanitize input
const { ObjectId } = require('mongodb');

// Reject operator injection
function sanitizeQuery(input) {
    if (typeof input !== 'string') {
        throw new Error('Invalid input type');
    }
    return input;
}

app.post('/login', (req, res) => {
    const username = sanitizeQuery(req.body.username);
    const password = sanitizeQuery(req.body.password);

    db.collection('users').findOne({
        username: username,
        password: password
    }).then(user => {
        // authentication
    });
});

// Better: use explicit properties, not dynamic objects
// Even better: use MongoDB schema validation
db.createCollection("users", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["username", "password"],
            properties: {
                username: { bsonType: "string" },
                password: { bsonType: "string" }
            }
        }
    }
});
```

### MongoDB Security Configuration

```yaml
# /etc/mongod.conf - SECURE
net:
  port: 27017
  bindIp: 10.0.0.5         # Bind to private IP, not 0.0.0.0
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/ca.pem

security:
  authorization: enabled     # CRITICAL: Enable auth
  keyFile: /etc/mongodb-keyfile  # Required for replica sets

setParameter:
  authenticationMechanisms: SCRAM-SHA-256  # Strong auth only

operationProfiling:
  mode: slowOp
  slowOpThresholdMs: 100
```

```bash
# MongoDB Docker - SECURE deployment
docker run -d \
  --name mongodb \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=$(cat /run/secrets/mongo_root_pass) \
  -e MONGO_INITDB_DATABASE=appdb \
  -v mongodb_data:/data/db \
  -v mongodb_config:/data/configdb \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  --network internal-net \
  mongo:7.0 --auth --tlsMode=requireTLS \
  --tlsCertificateKeyFile=/etc/ssl/certs/mongodb.pem \
  --bind_ip=10.0.0.5
```

### Redis: Vulnerable Code

```yaml
# VULNERABLE - AI-generated docker-compose.yml
services:
  redis:
    image: redis:latest
    ports:
      - "6379:6379"  # Exposed to the world!
    command: redis-server --protected-mode no  # Disabling protection!
```

```python
# VULNERABLE - AI-generated Redis connection
import redis
r = redis.Redis(host='localhost', port=6379)  # No password!
r.set('key', 'value')
```

### Redis: Secure Fix

```yaml
# SECURE - Redis docker-compose.yml
services:
  redis:
    image: redis:7.2-alpine
    ports:
      - "127.0.0.1:6379:6379"  # Only accessible from localhost
    volumes:
      - ./redis.conf:/usr/local/etc/redis/redis.conf
      - redis_data:/data
    command: redis-server /usr/local/etc/redis/redis.conf
    environment:
      - REDIS_PASSWORD_FILE=/run/secrets/redis_pass
    secrets:
      - redis_pass
    cap_drop:
      - ALL  # Drop all capabilities
    security_opt:
      - no-new-privileges:true
```

```conf
# redis.conf — SECURE
bind 127.0.0.1                    # Only localhost (or private IP)
port 6379
protected-mode yes                 # CRITICAL: Enable protected mode
requirepass your-strong-password   # CRITICAL: Set a password
rename-command FLUSHALL ""         # Disable dangerous commands
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command EVAL ""             # Disable Lua scripting if not needed
rename-command EVALSHA ""

# Security hardening
maxclients 100
timeout 300
tcp-keepalive 60
loglevel notice
logfile /var/log/redis/redis.log
always-show-logo no

# Persistence (if needed)
save 900 1
save 300 10
save 60 10000

# Slow log (detect abuse)
slowlog-log-slower-than 10000
slowlog-max-len 128

# ACL (Redis 6+) — much better than requirepass alone
user default off                    # Disable default user
user app_user on +@read +@write +@hash +@set -@dangerous ~* &* >strong-pass
```

```python
# SECURE - Redis connection
import redis
import os

r = redis.Redis(
    host='127.0.0.1',
    port=6379,
    password=os.environ.get('REDIS_PASSWORD'),
    ssl=True,
    ssl_ca_certs='/etc/ssl/certs/ca.pem',
    socket_connect_timeout=5,
    socket_timeout=5,
    retry_on_timeout=True,
    health_check_interval=30
)
```

### Elasticsearch: Vulnerable Code

```yaml
# VULNERABLE - AI-generated docker-compose.yml
services:
  elasticsearch:
    image: elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false    # Disabling security!
      - xpack.security.transport.ssl.enabled=false
    ports:
      - "9200:9200"     # Exposed REST API!
      - "9300:9300"
```

```python
# VULNERABLE - AI-generated Elasticsearch client
from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200")  # No auth, no TLS!
```

### Elasticsearch: Secure Fix

```yaml
# SECURE - Elasticsearch docker-compose.yml
services:
  elasticsearch:
    image: elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true               # ENABLE security
      - xpack.security.authc.api_key.enabled=true
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.security.transport.ssl.key=/usr/share/elasticsearch/config/certs/transport.key
      - xpack.security.transport.ssl.certificate=/usr/share/elasticsearch/config/certs/transport.crt
      - xpack.security.transport.ssl.certificate_authorities=/usr/share/elasticsearch/config/certs/ca.crt
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=/usr/share/elasticsearch/config/certs/http.key
      - xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/certs/http.crt
      - xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/certs/ca.crt
      - ELASTIC_PASSWORD_FILE=/run/secrets/elastic_pass
    ports:
      - "127.0.0.1:9200:9200"  # Localhost only
    volumes:
      - es_data:/usr/share/elasticsearch/data
      - ./certs:/usr/share/elasticsearch/config/certs:ro
    secrets:
      - elastic_pass
```

```python
# SECURE - Elasticsearch client with auth and TLS
from elasticsearch import Elasticsearch
import os

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=(os.environ['ES_USER'], os.environ['ES_PASS']),
    ca_certs="/etc/ssl/certs/ca.pem",
    verify_certs=True,
    request_timeout=30,
    max_retries=3,
    retry_on_timeout=True
)
```

### Elasticsearch: Schema Security

```python
# SECURE - Disable dynamic mapping, use explicit mapping
PUT /secure_index
{
  "settings": {
    "index.mapping.dynamic": false,  # Prevent mapping injection
    "index.mapping.depth.limit": 20,
    "index.mapping.field_name_length.limit": 100,
    "index.mapping.total_fields.limit": 1000
  },
  "mappings": {
    "dynamic": false,  # Strict mode: "strict" rejects unknown fields
    "properties": {
      "user_id": { "type": "keyword" },
      "email": { "type": "keyword" },
      "created_at": { "type": "date" }
    }
  }
}
```

---

## 4. Real Incidents and CVEs

### CVE-2024-10921 — MongoDB Buffer Over-Read via Malformed BSON
- **CVSS 3.1:** 6.8 (MEDIUM) — MongoDB CNA score (AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H); NVD adopted an 8.1 High primary
- **Published:** 2024-11-14
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-10921
- **Description:** An authorized user may trigger crashes or receive the contents of buffer over-reads of Server memory by issuing specially crafted requests that construct malformed BSON. Affects MongoDB v5.0 prior to 5.0.30, v6.0 prior to 6.0.19, v7.0 prior to 7.0.15, and v8.0 prior to 8.0.3.
- **CWE:** CWE-158 (Improper Neutralization of Null Byte or NUL Character)
- **Relevance to AI-Generated Apps:** AI-generated data pipelines often serialize/deserialize BSON directly without validation, putting unauthenticated or low-privilege users in a position to exploit buffer overflow conditions.

### CVE-2024-46981 — Redis Lua Script Remote Code Execution
- **CVSS 3.1:** 7.0 (HIGH) — Redis CNA score (AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H), reflecting the authenticated-user precondition; NVD adopted a 9.8 Critical primary
- **Published:** 2025-01-06
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-46981
- **Description:** An authenticated user may use a specially crafted Lua script to manipulate the garbage collector and potentially lead to remote code execution. Fixed in Redis 7.4.2, 7.2.7, and 6.2.17.
- **CWE:** CWE-416 (Use After Free)
- **Relevance to AI-Generated Apps:** AI-generated Redis configurations frequently enable Lua scripting (default) and use `requirepass` without ACL restrictions. Any authenticated user can exploit this. AI models often assign the same weak password to all services.

### CVE-2024-31449 — Redis Lua Stack Buffer Overflow RCE
- **CVSS 3.1:** 8.8 (HIGH) — NVD primary (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H); Redis CNA scores it 7.0 High. CWE-121 (Stack Buffer Overflow)
- **Published:** 2024-04-17
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-31449
- **Description:** Stack buffer overflow in Redis Lua scripting (CVE-2024-31449) allows authenticated users to achieve remote code execution. Affects all versions with Lua scripting; fixed in Redis 6.2.16, 7.2.6, and 7.4.1.
- **Relevance to AI-Generated Apps:** Demonstrates the risk of running any Lua scripts (including those generated by AI for Redis-based computation or caching) without proper ACL restrictions.

### CVE-2024-52980 — Elasticsearch DoS via Recursion
- **CVSS 3.1:** 6.5 (MEDIUM)
- **Published:** 2025-04-08
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-52980
- **Description:** Uncontrolled resource consumption in Elasticsearch via large recursion in the `innerForbidCircularReferences` function of the `PatternBank` class, causing the Elasticsearch node to crash. Affects versions 7.17.0 through 8.15.0.
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Relevance to AI-Generated Apps:** AI-generated search implementations using Elasticsearch `search_template` or `pattern`-based matching can trigger this DoS condition, especially when user input influences template parameters.

### CVE-2025-14847 — MongoBleed (MongoDB Unauthenticated Memory Leak)
- **CVSS 3.1:** 7.5 (HIGH)
- **Published:** 2025 (exploited in wild per Wiz.io)
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2025-14847
- **Description:** High-severity flaw in MongoDB's zlib decompression allows unauthenticated attackers to leak sensitive heap memory. Active exploitation in the wild identified by Wiz.io (MongoBleed).
- **Relevance to AI-Generated Apps:** Demonstrates critical risk of running MongoDB utilities like `mongodump` / `mongorestore` (common in AI-generated backup scripts) without TLS — compressed data streams become memory disclosure vectors.

### MongoDB Ransomware Crisis (2017)
- **Date:** January 2017
- **Scope:** Over 33,000 MongoDB instances hijacked; 22,900+ databases affected
- **Root Cause:** MongoDB default configuration had no authentication enabled; instances were exposed to the internet
- **Attack Vector:** Attackers scanned Shodan for open MongoDB ports (27017), connected without credentials, deleted all collections, and left ransom notes demanding Bitcoin
- **Source:** Dark Reading — "22,900 MongoDB Databases Affected in Ransomware Attack"
- **Relevance to AI-Generated Apps:** AI models continue to generate MongoDB configurations that replicate the exact conditions of this attack — no auth, no TLS, and exposed ports.

### Elasticsearch MOAB (Mother of All Breaches) — January 2024
- **Date:** January 2024
- **Scope:** 26 billion records (12 TB) in an unsecured Elasticsearch cluster
- **Root Cause:** Elasticsearch cluster with no authentication, exposed to the internet
- **Source:** SpyCloud — "The Most Notable Data Breaches of 2024"
- **Relevance to AI-Generated Apps:** Demonstrates that Elasticsearch without X-Pack security enabled (a common AI oversight) results in massive data exposure. AI-generated logging and search backends are routinely deployed without authentication.

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

## 7. References

- **MongoDB Security Documentation:** https://www.mongodb.com/docs/manual/security/
- **MongoDB Security Checklist:** https://www.mongodb.com/docs/manual/administration/security-checklist/
- **MongoDB CVE Advisories:** https://www.mongodb.com/resources/products/alerts
- **Redis Security Documentation:** https://redis.io/docs/management/security/
- **Redis ACL Documentation:** https://redis.io/docs/management/security/acl/
- **Elasticsearch Security Documentation:** https://www.elastic.co/guide/en/elasticsearch/reference/current/security.html
- **Elasticsearch Security Best Practices:** https://www.elastic.co/blog/how-to-prevent-elasticsearch-server-breach-securing-elasticsearch
- **OWASP NoSQL Injection:** https://owasp.org/www-community/attacks/NoSQL_Injection
- **OWASP Testing for NoSQL Injection:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **NVD CVE Database:** https://nvd.nist.gov/
- **Dark Reading — MongoDB Ransomware (2017):** https://www.darkreading.com/cloud-security/22900-mongodb-databases-affected-in-ransomware-attack
- **SpyCloud — Notable Data Breaches 2024 (MOAB Elasticsearch):** https://spycloud.com/blog/notable-data-breaches-2024/
- **Wiz.io — MongoBleed (CVE-2025-14847):** https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb
- **Cloud Security Alliance — Vibe Coding's Security Debt (2026):** https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/
- **Shodan Search Engine (exposed database discovery):** https://www.shodan.io/
