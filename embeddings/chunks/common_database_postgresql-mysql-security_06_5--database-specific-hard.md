---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "5. Database-Specific Hardening"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 6/10
---

## 5. Database-Specific Hardening

### PostgreSQL Hardening

**pg_hba.conf (Client Authentication):**
```
# Only allow encrypted connections from specific IP ranges
# TYPE  DATABASE  USER        ADDRESS            METHOD
hostssl all       app_user    10.0.0.0/8         scram-sha-256
hostssl all       app_user    172.16.0.0/12      scram-sha-256
# Reject all non-SSL connections
hostnossl all     all         0.0.0.0/0          reject
# Reject everything from the internet
hostssl all       all         0.0.0.0/0          reject
```

**SSL Certificate Authentication:**
```bash
# Generate client certificate
openssl req -new -text -nodes -subj '/CN=app_user' -out client.req
openssl rsa -in client.key -out client.key
openssl req -x509 -in client.req -text -key client.key -out client.crt

# pg_hba.conf entry
hostssl mydb app_user 10.0.0.0/8 cert clientcert=1
```

**Row-Level Security (RLS):**
```sql
-- Enable row-level security for multi-tenant data isolation
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_orders ON orders
    USING (user_id = current_setting('app.current_user_id')::int);
```

**Audit with pgaudit:**
```ini
# postgresql.conf
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'write,ddl,role'
pgaudit.log_level = 'notice'
```

**postgresql.conf security settings:**
```ini
# Connection security
listen_addresses = '10.0.0.5'       # Bind to specific IP, not '*'
port = 5432
max_connections = 100                # Prevent resource exhaustion
superuser_reserved_connections = 10  # Reserved for admin access
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'

# Statement timeout (prevents runaway queries)
statement_timeout = 30000            # 30 seconds
idle_in_transaction_session_timeout = 60000  # 1 minute
```

### MySQL Hardening

**mysql_secure_installation (Essential First Step):**
```bash
# Run and apply ALL recommendations:
mysql_secure_installation
# - Set root password
# - Remove anonymous users
# - Disallow root login remotely
# - Remove test database and access to it
# - Reload privilege tables
```

**bind-address Configuration:**
```ini
# /etc/mysql/my.cnf
[mysqld]
# Only listen on private network interface
bind-address = 10.0.0.5
# Never use 0.0.0.0 or skip-networking=OFF for internet-facing
# Explicitly disable TCP on servers that don't need remote access
# skip-networking  (uncomment for local-only)
```

**validate_password Plugin:**
```sql
INSTALL COMPONENT 'file://component_validate_password';
SET GLOBAL validate_password.policy = STRONG;
SET GLOBAL validate_password.length = 14;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count = 1;
SET GLOBAL validate_password.special_char_count = 1;
```

**MySQL Additional Hardening:**
```ini
[mysqld]
# Authentication
default_authentication_plugin = caching_sha2_password
# Logging
general_log = 0                     # Disable general log (but enable in audit)
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
# Security
local_infile = 0                    # Disable LOAD DATA LOCAL
max_allowed_packet = 64M            # Prevent resource issues
skip_symbolic_links = 1             # Prevent symlink attacks
expire_logs_days = 7                # Binary log retention
```

---