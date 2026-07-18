---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "2. Firewall Configuration"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 4/12
---

## 2. Firewall Configuration

### 2.1 Choose Your Tool

| Tool | Use Case | Complexity |
|------|----------|------------|
| `iptables` | Legacy, direct netfilter control | Medium |
| `nftables` | Modern replacement for iptables | Medium |
| `ufw` | Ubuntu's frontend for iptables | Low |
| `firewalld` | RHEL/CentOS/Fedora dynamic firewall | Low–Medium |

**Recommendation:** Use `nftables` on new deployments (default in Debian 11+, RHEL 9+). Use `ufw` for simplicity on single-purpose servers.

### 2.2 Default Deny Policy

```bash
# nftables
nft add rule inet filter input policy drop
nft add rule inet filter forward policy drop
nft add rule inet filter output policy accept
```

An explicit default-deny policy ensures that only intentionally exposed services are reachable.

### 2.3 Expose Only Necessary Ports

```bash
# Example: Web server
nft add rule inet filter input tcp dport { 80, 443 } accept
nft add rule inet filter input tcp dport 22 accept  # SSH (or custom port)
nft add rule inet filter input ct state established,related accept
```

**Never expose:** MongoDB (27017), Redis (6379), PostgreSQL (5432), MySQL (3306), Cassandra (9042), Kafka (9092), RabbitMQ (5672, 15672), Docker daemon (2375/2376), Elasticsearch (9200), or admin panels without VPN/tunnel.

### 2.4 Rate Limiting

```bash
# nftables rate limit (max 10 new connections per second on SSH)
nft add chain inet filter input '{ policy drop; }'
nft add rule inet filter input tcp dport 22 ct state new limit rate 10/second accept
nft add rule inet filter input tcp dport 22 ct state new log prefix "SSH RATE LIMIT: " drop

# connlimit (max 3 concurrent SSH connections from same source)
iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j REJECT
```

---