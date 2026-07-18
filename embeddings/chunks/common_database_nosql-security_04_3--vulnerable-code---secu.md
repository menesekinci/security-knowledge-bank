---
source: "common/database/nosql-security.md"
title: "NoSQL Database Security for AI-Generated Applications"
heading: "3. Vulnerable Code + Secure Fix per Database"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, incidents, injection, nosql, prevention, real, vulnerability]
chunk: 4/8
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