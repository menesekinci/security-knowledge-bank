---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 8/10
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