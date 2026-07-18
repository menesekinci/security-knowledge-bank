---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "2. Kafka Security"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 4/10
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