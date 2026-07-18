---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "6. fail2ban Configuration"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 8/12
---

## 6. fail2ban Configuration

### 6.1 Base Configuration

```bash
apt install fail2ban
```

**`/etc/fail2ban/jail.local`:**
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@example.com
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3

# Web server: nginx
[nginx-http-auth]
enabled = true
logpath = /var/log/nginx/error.log
maxretry = 5

# Web server: Apache
[apache-auth]
enabled = true
logpath = /var/log/apache2/error.log
maxretry = 5

# WordPress brute force
[wordpress]
enabled = true
logpath = /var/log/nginx/access.log
maxretry = 10
findtime = 60
```

### 6.2 Custom Filters for Database Services

**PostgreSQL jail (`/etc/fail2ban/jail.d/postgresql.conf`):**
```ini
[postgresql]
enabled = true
filter = postgresql
logpath = /var/log/postgresql/postgresql-*.log
maxretry = 5
```

**MySQL/MariaDB jail:**
```ini
[mysqld-auth]
enabled = true
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
```

### 6.3 Whitelisting

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
```

Always whitelist internal monitoring/management IPs.

---