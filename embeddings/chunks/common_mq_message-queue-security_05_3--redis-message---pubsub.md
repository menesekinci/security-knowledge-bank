---
source: "common/mq/message-queue-security.md"
title: "Message Queue Security"
heading: "3. Redis Message / PubSub Security"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, kafka, message, rabbitmq, redis, security, table]
chunk: 5/10
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