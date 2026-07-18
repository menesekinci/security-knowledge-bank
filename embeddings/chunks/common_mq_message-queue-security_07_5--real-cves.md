---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "5. Real CVEs"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 7/10
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