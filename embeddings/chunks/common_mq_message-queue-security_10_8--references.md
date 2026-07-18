---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "8. References"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 10/10
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