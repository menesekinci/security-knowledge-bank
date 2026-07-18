---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "4. How AI / Vibe Coding Generates Insecure Configs"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 6/10
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