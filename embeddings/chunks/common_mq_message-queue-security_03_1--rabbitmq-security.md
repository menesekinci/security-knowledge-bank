---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "1. RabbitMQ Security"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 3/10
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