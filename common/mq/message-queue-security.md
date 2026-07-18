# Message Queue Security

> **Severity:** High  
> **CWE:** CWE-287 (Improper Authentication), CWE-311 (Missing Encryption of Sensitive Data), CWE-200 (Exposure of Sensitive Information), CWE-284 (Improper Access Control)  
> **AI Generation Risk:** High — AI frequently generates code that connects to message brokers without authentication or TLS, exposing data pipelines.  
> **Last Updated:** 2025-07-17

---

## Table of Contents

1. [RabbitMQ Security](#1-rabbitmq-security)
2. [Kafka Security](#2-kafka-security)
3. [Redis Message / PubSub Security](#3-redis-message--pubsub-security)
4. [How AI / Vibe Coding Generates Insecure Configs](#4-how-ai--vibe-coding-generates-insecure-configs)
5. [Real CVEs](#5-real-cves)
6. [Prevention Checklist](#6-prevention-checklist)
7. [Vibe-Coding Red Flags](#7-vibe-coding-red-flags)
8. [References](#8-references)

---

## 1. RabbitMQ Security

RabbitMQ is the most widely deployed open-source message broker. Its default configuration prioritizes ease of getting started over security — making misconfigured instances a common finding in penetration tests.

### 1.1 Default Credentials — guest/guest

**Critical:** The default `guest` user with password `guest` can only connect from `localhost`. However, many deployment scripts and Docker containers inadvertently remove this restriction.

```bash
# Remove or disable the default guest user
rabbitmqctl delete_user guest

# Or restrict to localhost only (default, but verify):
# In rabbitmq.conf:
loopback_users.guest = true
```

**Always create admin users with strong passwords:**
```bash
rabbitmqctl add_user admin '<strong-password-here>'
rabbitmqctl set_user_tags admin administrator
rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"
```

### 1.2 TLS Enforcement

RabbitMQ supports TLS for the AMQP protocol (port 5671), the management HTTP API (port 15671), and MQTT/STOMP. **Never expose AMQP without TLS in production.**

**`rabbitmq.conf` TLS configuration:**
```ini
# AMQP TLS
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/ca_certificate.pem
ssl_options.certfile   = /etc/rabbitmq/server_certificate.pem
ssl_options.keyfile    = /etc/rabbitmq/server_key.pem
ssl_options.verify     = verify_peer
ssl_options.fail_if_no_peer_cert = true

# Management UI TLS
management.listener.port = 15671
management.listener.ssl = true

# Disable plaintext listeners (optional but recommended for production)
listeners.tcp.default = 5672   # Can set to none to disable plain TCP
```

**Client connection enforcement:** Ensure all client libraries are configured to use `amqps://` (not `amqp://`). RabbitMQ does not automatically redirect plaintext to TLS.

### 1.3 Virtual Host (VHost) Isolation

VHosts are RabbitMQ's primary tenancy boundary. Each team or service should have its own VHost.

```bash
# Create isolated vhosts
rabbitmqctl add_vhost service_a
rabbitmqctl add_vhost service_b
rabbitmqctl add_vhost staging_team

# Grant permissions only to the relevant vhost
rabbitmqctl set_permissions -p service_a service_a_user ".*" ".*" ".*"
```

**Permissions scoping:** The three regex patterns in `set_permissions` control:
1. **Configure** — Who can declare/delete queues, exchanges, bindings
2. **Write** — Who can publish messages
3. **Read** — Who can consume messages

```bash
# Least-privilege example: app can only write to exchanges starting with "orders."
rabbitmqctl set_permissions -p service_a order_producer "^order.*" "^order.*" ""
```

### 1.4 User Permission Scoping

| Permission | Resource Pattern | Example |
|------------|-----------------|---------|
| Configure | Queue name regex | `^orders\..*` |
| Write | Exchange name regex | `^orders-exchange$` |
| Read | Queue name regex | `^orders\.\d+$` |

Use the principle of least privilege: applications that only produce messages should not have consume permissions, and vice versa.

### 1.5 Shovel and Federation Auth

**Shovel** (cross-cluster message transfer) and **Federation** (exchange/queue federation) can expose credentials in configuration if not handled carefully.

```ini
# If using AMQP URI with embedded credentials, protect the config file
# rabbitmq.conf:
rabbitmq_shovel.dynamic = 0   # Disable dynamic shovels via management API
```

**For production, use long-lived credentials with restricted permissions dedicated to Shovel/Federation,** and configure them via the config file rather than the management UI.

### 1.6 Management UI Hardening

```ini
# Restrict management UI to internal network only
management.listener.ip = 10.0.0.0

# Disable management UI entirely on internet-facing brokers
# (Use Prometheus + Grafana for monitoring instead)
management.listener.port = 0   # Disables HTTP management
```

---

## 2. Kafka Security

Apache Kafka was designed for high-throughput data pipelines within trusted networks — its default configuration is PLAINTEXT with no authentication.

### 2.1 PLAINTEXT vs SSL/SASL

**Never use `PLAINTEXT` listeners in production.** The minimum viable configuration is `SSL` for encryption.

**`server.properties` — TLS listener:**
```ini
listeners=SSL://0.0.0.0:9093
advertised.listeners=SSL://broker.example.com:9093
ssl.keystore.location=/var/private/ssl/kafka.server.keystore.jks
ssl.keystore.password=changeit
ssl.key.password=changeit
ssl.truststore.location=/var/private/ssl/kafka.server.truststore.jks
ssl.truststore.password=changeit
ssl.client.auth=required    # Mutual TLS
```

**SASL authentication options (pick one):**

| Mechanism | Strength | Use Case |
|-----------|----------|----------|
| SASL/SCRAM-SHA-512 | Strong | General purpose, password-based |
| SASL/GSSAPI (Kerberos) | Very strong | Enterprise environments with existing KDC |
| SASL/PLAIN | Weak — cleartext | Only with TLS encryption |
| mTLS (SSL client auth) | Very strong | Certificate-based, no password management |

**Recommended: SASL/SCRAM + SSL:**
```ini
# server.properties
listeners=SASL_SSL://0.0.0.0:9093
sasl.enabled.mechanisms=SCRAM-SHA-512
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
security.inter.broker.protocol=SASL_SSL
```

```bash
# Create SCRAM users
kafka-configs.sh --zookeeper localhost:2181 --alter --add-config \
  'SCRAM-SHA-512=[password=strong-password]' --entity-type users --entity-name producer-app

kafka-configs.sh --zookeeper localhost:2181 --alter --add-config \
  'SCRAM-SHA-512=[password=strong-password]' --entity-type users --entity-name consumer-app
```

### 2.2 ACL-Based Topic Access Control

Kafka ACLs control which users can perform which operations on which resources. Enable with:

```ini
# server.properties
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
allow.everyone.if.no.acl.found=false   # Default deny!
super.users=User:admin
```

**Common ACL patterns:**
```bash
# Admin full access
kafka-acls.sh --authorizer-properties zookeeper.connect=localhost:2181 \
  --add --allow-principal User:admin --operation All --topic '*'

# Producer: write to orders topic
kafka-acls.sh --add --allow-principal User:producer-app \
  --operation Write --operation Describe --topic orders

# Consumer: read from orders-payments topic
kafka-acls.sh --add --allow-principal User:consumer-app \
  --operation Read --operation Describe --topic orders-payments \
  --group orders-group
```

**Group-level ACLs are critical** — without them, a consumer can use any consumer group and read from any offset position.

### 2.3 Encryption at Rest + In Transit

**In transit:** TLS (see §2.1) — mandatory.

**At rest:** Kafka stores data in its log directories (`log.dirs`). Enable at-rest encryption at the filesystem or disk level:

```bash
# LUKS-based disk encryption
cryptsetup luksFormat /dev/sdb
cryptsetup open /dev/sdb kafka-data
mkfs.ext4 /dev/mapper/kafka-data
mount /dev/mapper/kafka-data /var/lib/kafka/data

# Or use dm-crypt with LUKS on cloud volumes
```

For cloud deployments, use the provider's encryption (EBS encryption on AWS, Azure Disk Encryption, etc.).

### 2.4 Quota Management (DoS Prevention)

Without quotas, a single misbehaving producer or consumer can degrade the entire cluster.

```ini
# server.properties — default quotas
# Network bandwidth (bytes/sec)
quota.producer.default=536870912      # 512 MB/sec
quota.consumer.default=536870912      # 512 MB/sec

# Request rate (requests/sec)
client.quota.callback.static.produce=1000
client.quota.callback.static.fetch=1000
```

**Per-client overrides:**
```bash
kafka-configs.sh --alter --add-config \
  'producer_byte_rate=104857600,consumer_byte_rate=104857600' \
  --entity-type users --entity-name producer-app
```

### 2.5 Network Segmentation

```ini
# server.properties — separate listeners for internal vs external
listeners=INTERNAL://10.0.0.10:9092,EXTERNAL://0.0.0.0:9093
listener.security.protocol.map=INTERNAL:PLAINTEXT,EXTERNAL:SASL_SSL
advertised.listeners=INTERNAL://broker.internal:9092,EXTERNAL://kafka.example.com:9093
inter.broker.listener.name=INTERNAL
```

This allows internal communication on a fast, plaintext network while external clients authenticate over TLS.

---

## 3. Redis Message / PubSub Security

Redis is commonly used as a message broker via its PubSub feature, as well as for caching and session storage. **Redis is notoriously insecure out of the box** — it ships with no authentication and listens on all interfaces.

### 3.1 Redis Without AUTH → Data Exposure

By default, Redis listens on `0.0.0.0:6379` with no password. Shodan searches consistently find tens of thousands of unauthenticated Redis instances publicly accessible.

**Configuration (`redis.conf`):**
```ini
# REQUIRED: Set a strong password
requirepass <very-strong-random-password>

# Or use ACLs (Redis 6+)
aclfile /etc/redis/users.acl
```

**ACL file example (`/etc/redis/users.acl`):**
```
user default off
user pubsub-app on +@pubsub ~* >strong-password-here
user cache-app on +get +set ~cache:* >another-strong-password
```

### 3.2 Protected Mode

Redis 3.2+ includes a **protected mode** that restricts access to only `loopback` interfaces when no password is set.

```ini
# redis.conf
protected-mode yes
```

**However:** Protected mode can be circumvented — if your application binds to `0.0.0.0` explicitly (common in Docker), protected mode is bypassed. Always set a password.

### 3.3 Renaming Dangerous Commands

Even with authentication, if an attacker gains access, dangerous Redis commands can be used to compromise the host or destroy data.

```ini
# redis.conf — rename to hard-to-guess names
rename-command FLUSHALL "8a9f3b7c1d2e4f5a"
rename-command FLUSHDB "b2c3d4e5f6a7b8c9"
rename-command CONFIG "d1e2f3a4b5c6d7e8"
rename-command DEBUG "e5f6a7b8c9d0e1f2"
rename-command SAVE "f0a1b2c3d4e5f6a7"
rename-command SHUTDOWN "a1b2c3d4e5f6a7b8"

# Or disable them entirely (preferred if not needed)
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command SAVE ""
rename-command SHUTDOWN ""
rename-command EVAL ""
rename-command EVALSHA ""
```

### 3.4 TLS for Redis 6+

Redis 6.0+ supports TLS natively:

```ini
# redis.conf
tls-port 6380
port 0                          # Disable plaintext port

tls-cert-file /etc/redis/redis.crt
tls-key-file /etc/redis/redis.key
tls-ca-cert-file /etc/redis/ca.crt
tls-auth-clients yes
tls-replication yes
```

### 3.5 Binding to Correct Interfaces

```ini
# redis.conf
# BAD: bind 0.0.0.0   — binds to all interfaces
# GOOD:
bind 127.0.0.1                 # Local only
# OR for multi-instance on same host:
bind 10.0.0.5 127.0.0.1       # Internal IP + localhost
```

### 3.6 Running Without Protected Mode on Public IP

This is one of the most common Redis misconfigurations found in cloud environments. When all three of these are true, anyone on the internet can access your Redis data:

1. `protected-mode no`
2. `bind 0.0.0.0` or public IP
3. No `requirepass` set (or `requirepass` is commented out)

**Detection:**
```bash
# Check if Redis is exposed
ss -tlnp | grep 6379

# Check config
redis-cli CONFIG GET protected-mode
redis-cli CONFIG GET requirepass
redis-cli CONFIG GET bind
```

---

## 4. How AI / Vibe Coding Generates Insecure Configs

AI code generators and large language models frequently produce message queue configurations that are insecure by default. Below are the most common patterns observed:

### 4.1 "Add Redis for caching" → No Password, No TLS, Default Port

```python
# ❌ AI-generated insecure snippet
import redis
r = redis.Redis(host='my-server', port=6379)  # Default port, no password!
r.set('key', 'value')
```

**What AI typically omits:**
- `password=` parameter
- `ssl=True` and `ssl_ca_certs`
- `socket_connect_timeout` (prevents hanging on unreachable hosts)
- `socket_timeout`

**✅ Secure version:**
```python
import redis
r = redis.Redis(
    host='my-server',
    port=6380,
    password='<strong-password>',
    ssl=True,
    ssl_ca_certs='/etc/ssl/certs/ca-certificates.crt',
    socket_connect_timeout=5,
    socket_timeout=5,
    decode_responses=True
)
```

### 4.2 "Set up RabbitMQ" → guest/guest, No VHost Isolation

```python
# ❌ AI-generated insecure snippet
import pika
connection = pika.BlockingConnection(pika.URLParameters(
    'amqp://guest:guest@my-rabbit:5672/'))  # Default credentials!
```

**✅ Secure version:**
```python
import pika
connection = pika.BlockingConnection(pika.URLParameters(
    'amqps://app-user:strong-password@my-rabbit:5671/service_vhost'))
```

### 4.3 "Stream data with Kafka" → PLAINTEXT, No ACLs

```python
# ❌ AI-generated insecure snippet
from kafka import KafkaProducer
producer = KafkaProducer(
    bootstrap_servers=['my-kafka:9092']  # PLAINTEXT, no auth!
)
```

**✅ Secure version:**
```python
from kafka import KafkaProducer
producer = KafkaProducer(
    bootstrap_servers=['my-kafka:9093'],
    security_protocol='SASL_SSL',
    sasl_mechanism='SCRAM-SHA-512',
    sasl_plain_username='producer-app',
    sasl_plain_password='strong-password',
    ssl_cafile='/etc/ssl/certs/ca-certificates.crt'
)
```

### 4.4 Docker Compose Without Security

```yaml
# ❌ Insecure docker-compose snippet
services:
  redis:
    image: redis:latest
    ports:
      - "6379:6379"    # Exposed to host network, no password

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"    # AMQP without TLS
      - "15672:15672"  # Management UI without auth hardening
```

**✅ Secure version:**
```yaml
services:
  redis:
    image: redis:7-alpine
    command: >
      --requirepass ${REDIS_PASSWORD}
      --tls-port 6380
      --port 0
      --tls-cert-file /certs/redis.crt
      --tls-key-file /certs/redis.key
      --tls-ca-cert-file /certs/ca.crt
    ports:
      - "127.0.0.1:6380:6380"   # Only localhost
    volumes:
      - ./certs:/certs:ro
    networks:
      - internal

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "127.0.0.1:15672:15672"  # Management only from localhost
    environment:
      RABBITMQ_ERLANG_COOKIE: ${RABBITMQ_COOKIE}
    volumes:
      - ./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
      - ./certs:/etc/rabbitmq/certs:ro
    networks:
      - internal
```

---

## 5. Real CVEs

### 5.1 Redis CVEs

#### CVE-2025-49844 — RediShell (Redis Lua RCE)

| Field | Value |
|-------|-------|
| **CVSS** | 9.9 (CRITICAL) |
| **CWE** | CWE-416 (Use After Free) |
| **Affected** | Redis ≤ 8.2.1 (all versions with Lua scripting) |
| **Fixed in** | Redis 8.2.2 |

**Description:** An authenticated user can craft a Lua script that manipulates the garbage collector to trigger a use-after-free, leading to remote code execution. This vulnerability was discovered by an autonomous AI agent (Wiz Research) and went unnoticed for 13 years.

**Mitigation:** Upgrade to Redis 8.2.2 or later. As a workaround, prevent users from executing Lua scripts (disable `EVAL`/`EVALSHA` or restrict via ACLs).

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-49844

#### CVE-2024-31449 — Redis Lua Stack Buffer Overflow

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (HIGH) |
| **CWE** | CWE-20 (Improper Input Validation), CWE-121 (Stack Buffer Overflow) |
| **Affected** | All Redis versions with Lua scripting |
| **Fixed in** | Redis 6.2.16, 7.2.6, 7.4.1 |

**Description:** An authenticated user may use a specially crafted Lua script to trigger a stack buffer overflow in the bit library, potentially leading to remote code execution. No workarounds exist — upgrading is mandatory.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-31449

#### CVE-2024-31227 — Redis ACL Denial of Service

| Field | Value |
|-------|-------|
| **CVSS** | 4.4 (MEDIUM) |
| **CWE** | CWE-20 (Improper Input Validation) |
| **Affected** | Redis 7.x prior to 7.2.6 and 7.4.1 |
| **Fixed in** | Redis 7.2.6, 7.4.1 |

**Description:** An authenticated user with sufficient privileges can create a malformed ACL selector that, when accessed, triggers a server panic and subsequent denial of service.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-31227

### 5.2 RabbitMQ CVEs

#### CVE-2024-51988 — RabbitMQ Queue Deletion Permission Bypass

| Field | Value |
|-------|-------|
| **CVSS** | 6.5 (MEDIUM) |
| **CWE** | CWE-284 (Improper Access Control) |
| **Affected** | RabbitMQ < 3.12.11 |
| **Fixed in** | RabbitMQ 3.12.11, 3.13.0, 4.0.0 |

**Description:** Queue deletion via the HTTP API did not verify the `configure` permission of the user. Users with valid credentials, some permissions for the target virtual host, and HTTP API access could delete queues they had no deletion permissions for. As a workaround, disable the management plugin and use Prometheus/Grafana for monitoring.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-51988

#### CVE-2024-27198 — (Related) Web Management Auth Bypass in JetBrains TeamCity

While not a RabbitMQ-native CVE, this demonstrates the risk of management interfaces: **CVE-2024-27198** (CVSS 9.8, CRITICAL) allowed authentication bypass in TeamCity's web component, enabling admin actions without authentication.

### 5.3 Kafka CVEs

#### CVE-2024-32030 — Kafka UI JMX Deserialization RCE

| Field | Value |
|-------|-------|
| **CVSS** | 8.1 (HIGH) |
| **CWE** | CWE-94 (Code Injection), CWE-502 (Deserialization of Untrusted Data) |
| **Affected** | Kafka UI (third-party web UI for Kafka management) |
| **Fixed in** | Various versions depending on the UI distribution |

**Description:** Kafka UI's API allows users to connect to different Kafka brokers by specifying their network address and port. JMX monitoring is based on the RMI protocol, which is inherently susceptible to deserialization attacks. An attacker can exploit this by connecting the Kafka UI backend to their own malicious broker, achieving remote code execution.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-32030

#### CVE-2024-4173 — Kafka Exposure on WAN Interface

| Field | Value |
|-------|-------|
| **CVSS** | 9.8 (CRITICAL) |
| **CWE** | CWE-200 (Exposure of Sensitive Information) |
| **Affected** | Brocade SANnav (exposes Kafka on WAN interface) |
| **Fixed in** | Vendor advisory |

**Description:** A vulnerability in Brocade SANnav exposes Kafka on the WAN interface. An unauthenticated attacker can perform various attacks including denial of service against Brocade SANnav, with the Kafka broker serving as an attack vector through the exposed network interface.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-4173

---

## 6. Prevention Checklist

### RabbitMQ
- [ ] **Default guest user disabled** or restricted to localhost
- [ ] **TLS enabled** on AMQP (port 5671) and management (15671)
- [ ] **Plaintext listeners disabled** (or at least listen only on internal interfaces)
- [ ] **VHost isolation** per service/team with least-privilege permissions
- [ ] **User permissions scoped** — configure/write/read limited to needed resources
- [ ] **Management UI restricted** to internal network or disabled entirely
- [ ] **Erlang cookie secured** and not shared publicly (stored in secrets manager)
- [ ] **Shovel/Federation credentials** stored in config files, not management API
- [ ] **Plugin audit** — disable unused plugins (e.g., `rabbitmq_mqtt`, `rabbitmq_stomp` if not used)
- [ ] **Connection rate limiting** via `channel_max` and `connection_max` in `rabbitmq.conf`

### Kafka
- [ ] **PLAINTEXT listeners never used in production**
- [ ] **SSL/SASL enabled** — SASL/SCRAM or Kerberos recommended
- [ ] **ACL authorizer enabled** with `allow.everyone.if.no.acl.found=false`
- [ ] **Topic-level ACLs** for read/write/describe/consume operations
- [ ] **Group-level ACLs** configured for consumer groups
- [ ] **mTLS or SASL** for inter-broker communication
- [ ] **At-rest encryption** — LUKS or cloud-provider encryption for log directories
- [ ] **Quotas configured** — producer/consumer byte rates to prevent DoS
- [ ] **Network segmentation** — separate internal/external listeners
- [ ] **Kafka version up-to-date** with security patches applied
- [ ] **ZooKeeper secured** with SASL authentication (or use KRaft mode)
- [ ] **JMX not exposed** on public interfaces (CVE-2024-32030 vector)

### Redis (PubSub / Caching)
- [ ] **Authentication enabled** — `requirepass` with strong password
- [ ] **ACLs configured** (Redis 6+) — least privilege per application
- [ ] **Protected mode ON** (`protected-mode yes`)
- [ ] **Bound to specific interfaces** — never `0.0.0.0` unless behind a VPN
- [ ] **Dangerous commands renamed or disabled** — FLUSHALL, CONFIG, DEBUG, SAVE, SHUTDOWN, EVAL
- [ ] **TLS enabled** on a separate port (6380), plaintext port disabled
- [ ] **Running as non-root user** — never run Redis as root
- [ ] **Key space notifications** disabled unless explicitly needed (`notify-keyspace-events ""`)
- [ ] **`maxmemory` and `maxmemory-policy`** configured to prevent OOM
- [ ] **Redis version ≥ 6.2.16** (latest security patches)
- [ ] **Container ports not mapped to host** unless intentional (use `127.0.0.1:` prefix)
- [ ] **`rename-command` used** to disable or obfuscate dangerous commands

### General
- [ ] **All message brokers on private subnets** — never directly internet-facing
- [ ] **Credentials stored in secrets manager** — not in code, env files, or helm values files
- [ ] **Connection strings tested** for TLS enforcement (reject plaintext fallback)
- [ ] **Monitoring alerts** for authentication failures (rapid failed logins → incident)
- [ ] **CVE monitoring** via NVD feeds or GitHub security advisories for critical dependencies
- [ ] **Regular security audits** — scan exposed ports with nmap/nmap, verify TLS with testssl.sh

---

## 7. Vibe-Coding Red Flags

Common patterns produced by AI code generators that lead to message queue security issues:

| Red Flag | Why It's Dangerous | What to Use Instead |
|----------|-------------------|---------------------|
| `redis.Redis(host='server')` without password | Exposes all Redis data | Add `password=` and `ssl=True` |
| `amqp://guest:guest@host:5672/` | Default credentials, no TLS | `amqps://user:pass@host:5671/vhost` |
| `KafkaProducer(bootstrap_servers=['host:9092'])` | PLAINTEXT, no auth | Add `security_protocol='SASL_SSL'` |
| `rabbitmq:3-management` with default config | TLS not configured, guest enabled | Use custom config with TLS enforced |
| `redis:latest` in Docker Compose | No password, exposed to host | Add command args with `--requirepass` |
| `expose: [6379, 5672]` in Docker without TLS | Service exposed to other containers unencrypted | Use TLS and authenticate |
| Hardcoded passwords in source code | Exposed in Git history | Load from env vars / secrets manager |
| `allow.everyone.if.no.acl.found=true` (Kafka) | Kafka default | Set to `false` and define ACLs |
| `protected-mode no` (Redis) | Disables safety net | Keep `yes` and set a password |
| Not setting `tls-auth-clients` | No client certificate verification | Set `tls-auth-clients yes` |
| `listeners=PLAINTEXT://0.0.0.0:9092` (Kafka) | Unencrypted, all interfaces | Use `SASL_SSL://` on specific IP |
| `requirepass` commented out | No password | Uncomment and set strong password |
| No VHost/per-namespace isolation | Cross-service data leakage | Use separate VHosts/namespaces |

---

## 8. References

### RabbitMQ
- **RabbitMQ SSL/TLS Configuration:** https://www.rabbitmq.com/ssl.html
- **RabbitMQ Access Control:** https://www.rabbitmq.com/access-control.html
- **RabbitMQ Production Checklist:** https://www.rabbitmq.com/production-checklist.html
- **CVE-2024-51988:** https://nvd.nist.gov/vuln/detail/CVE-2024-51988

### Kafka
- **Kafka Security Documentation:** https://kafka.apache.org/documentation/#security
- **Kafka ACLs:** https://docs.confluent.io/platform/current/kafka/authorization.html
- **Kafka Security Best Practices:** https://www.confluent.io/blog/apache-kafka-security-best-practices/
- **CVE-2024-32030:** https://nvd.nist.gov/vuln/detail/CVE-2024-32030
- **CVE-2024-4173:** https://nvd.nist.gov/vuln/detail/CVE-2024-4173

### Redis
- **Redis Security:** https://redis.io/docs/management/security/
- **Redis ACL Documentation:** https://redis.io/docs/management/security/acl/
- **Redis TLS Support:** https://redis.io/docs/management/security/encryption/
- **CVE-2024-31449:** https://nvd.nist.gov/vuln/detail/CVE-2024-31449
- **CVE-2024-31227:** https://nvd.nist.gov/vuln/detail/CVE-2024-31227
- **CVE-2025-49844:** https://nvd.nist.gov/vuln/detail/CVE-2025-49844

### General
- **OWASP Message Queue Security:** https://owasp.org/www-project-cheat-sheets/
- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks/
- **NVD (National Vulnerability Database):** https://nvd.nist.gov/

---

> **Previous:** See [`../server/linux-server-hardening.md`](../server/linux-server-hardening.md) for operating-system-level hardening.
