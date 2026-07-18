---
source: "common/engineering/security-architecture-patterns.md"
title: "Security Architecture Patterns"
heading: "4. Logging & Monitoring Architecture"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [access, common-vuln, encryption, identity, logging, monitoring, network, security, segmentation, strategies]
chunk: 5/7
---

## 4. Logging & Monitoring Architecture

### 4.1 Centralized Logging

Centralized logging collects logs from every service, host, and network device into a single searchable platform.

| Platform | Strengths | Weaknesses |
|---|---|---|
| **ELK (Elasticsearch, Logstash, Kibana)** | Open source, highly customizable, full-text search | Operational overhead, scaling Elasticsearch |
| **Loki (Grafana)** | Designed for K8s, cheap log ingestion, integrates with Prometheus | Limited structured query, younger ecosystem |
| **Datadog / Splunk** | Managed, out-of-the-box integrations, AI-driven alerts | Cost (especially at high volume), vendor lock-in |

**Log categories and retention:**
| Category | Examples | Retention | Cost sensitivity |
|---|---|---|---|
| **Debug logs** | Application traces, verbose request logs | 7–30 days | High — largest volume |
| **Operational logs** | Access logs, error rates, latency | 30–90 days | Medium |
| **Audit logs** | Auth events, permission changes, data access | 1–7 years (compliance) | Low — small volume, high value |

### 4.2 Audit Trails vs. Debugging Logs

These serve fundamentally different purposes and should be treated differently:

| Dimension | Audit Trail | Debug Log |
|---|---|---|
| **Purpose** | Non-repudiation, compliance, forensic investigation | Troubleshooting, performance analysis |
| **Content** | Who did what, when, from where, to what resource | Variable dumps, stack traces, timing data |
| **Immutability** | Must be append-only, tamper-evident | Can be overwritten or truncated |
| **Trigger** | Defined security events (auth, admin actions) | Every request or deterministic sample |
| **Format** | Structured (JSON, CEF) with schema enforcement | Semi-structured or freeform |
| **Access** | Restricted (read-only for most engineers) | Broad (anyone debugging) |

**Rule of thumb:** If the log record would hold up in court or during an audit, it's an audit trail. If it helps you find a bug, it's a debug log. Never put debug-log verbosity into an audit trail — the signal drowns in noise.

### 4.3 Log Integrity

Logs are evidence — they must be trustworthy. An attacker who compromises a system should not be able to erase their tracks by modifying logs.

**Forwarding (immutable pipeline):**
```
App → Filebeat/Fluentd → Message Queue (Kafka) → SIEM → WORM Storage
```
- Logs should be forwarded off the host immediately (syslog-ng, Filebeat, Fluentd).
- Buffering on the host is acceptable (for network blips), but the primary store should be the SIEM, not the local disk.
- Use TLS for log shipping to prevent tampering in transit.

**WORM (Write Once, Read Many) storage:**
- Final destination for audit logs should be immutable: S3 Object Lock, Azure Immutable Blob, physical WORM media.
- Retention policy is enforced by the storage layer, not by application code (apps can be hacked; the storage layer's immutability is harder to bypass).
- For compliance (PCI DSS, SOC 2, HIPAA), WORM storage with a retention period of at least 1 year is often required.

**Log integrity verification:**
- Cryptographic signing of log entries (e.g., syslog with TLS, or per-entry HMAC).
- Periodic integrity checks: compute a hash of the log range and compare against a stored value.
- Chain hashing (each entry includes the hash of the previous entry) — similar to a blockchain. If any entry is modified, its hash changes and all subsequent hashes break.

---