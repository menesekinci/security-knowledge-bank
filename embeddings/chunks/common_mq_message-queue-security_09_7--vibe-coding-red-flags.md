---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "7. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 9/10
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