# PostgreSQL & MySQL Security for AI-Generated Applications

- **Severity:** Critical
- **CWE:** CWE-798 (Hardcoded Credentials), CWE-311 (Missing Encryption of Sensitive Data), CWE-89 (SQL Injection), CWE-862 (Missing Authorization), CWE-326 (Weak Cryptography)
- **AI Generation Risk:** Very High

---

## 1. Vulnerability Explanation

AI-generated and "vibe-coded" applications consistently exhibit the same database security failures. Large Language Models (LLMs) are trained on public code repositories, tutorials, and quick-start guides — which overwhelmingly prioritize convenience over security. The result is production applications with gaping database security holes.

### Common AI-Generated Database Security Failures

**1. Hardcoded Connection Strings**
AI models routinely generate connection strings with plaintext credentials embedded directly in source code:

```python
# PostgreSQL — AI-generated
conn = psycopg2.connect("postgresql://admin:SuperSecret123@db.example.com:5432/production")
```

```javascript
// MySQL — AI-generated
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',
  database: 'app'
});
```

These credentials end up committed to Git repositories, hardcoded in Docker images, embedded in frontend bundles, and exposed in CI/CD logs.

**2. Disabled SSL/TLS**
AI code often disables encryption to avoid configuration complexity:

- PostgreSQL: `sslmode=disable` or `sslmode=prefer` (falls back to unencrypted)
- MySQL: `?useSSL=false` or `?useSSL=false&allowPublicKeyRetrieval=true`
- The `allowPublicKeyRetrieval=true` flag alone allows MITM attacks to steal the public key and decrypt traffic

**3. Default Ports, No Firewall Rules**
AI-generated deployment scripts typically use default ports (PostgreSQL: 5432, MySQL: 3306) without implementing firewall rules. Combined with cloud deployment, this frequently results in databases directly exposed to the internet.

**4. Excessive Database Permissions**
AI models default to the connection string they find — often the `postgres` superuser or MySQL `root` account. The application ends up running with:
- Database superuser privileges
- Ability to `DROP`, `TRUNCATE`, or `ALTER` tables
- Ability to read `pg_shadow`, `mysql.user` tables
- Write access to system schemas

**5. No Connection Pooling Limits**
AI-generated code typically opens direct connections without pooling, leading to:
- Connection exhaustion under load
- No query timeout configuration
- No statement timeout or termination limits
- No max connection limits per application

**6. Raw SQL Concatenation**
Despite the ubiquity of ORMs, AI often generates raw SQL string concatenation — especially when the prompt asks for complex queries that the model's training data shows constructed via string formatting.

**7. Missing or Weak Authentication**
AI-generated Docker Compose files frequently omit password configuration or use weak, guessable defaults.

---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

### Prompt Patterns That Trigger Insecure Code

| Risk Level | Prompt Pattern | Typical LLM Output |
|---|---|---|
| Critical | "Create a quick API with PostgreSQL backend" | Hardcoded connection string, no env vars |
| Critical | "Deploy my app with Docker Compose" | Default creds, exposed ports, no auth |
| High | "Connect to MySQL database in Python" | `useSSL=false`, `allowPublicKeyRetrieval=true` |
| High | "Write a search endpoint for my products" | Raw SQL `f"... WHERE name LIKE '%{query}%'"` |
| High | "Add a database user for my application" | GRANT ALL PRIVILEGES, superuser account |
| Medium | "Set up PostgreSQL for development" | `sslmode=disable`, trust auth in pg_hba.conf |
| Medium | "Fix my database connection error" | Disable SSL, relax auth requirements |

### Why LLMs Produce Insecure Database Code

- **Training data skew**: Tutorial code (dev environments) outweighs production security patterns
- **Convenience bias**: Models optimize for "code that works immediately" over "code that is secure"
- **Missing context**: LLMs don't see your network topology, compliance requirements, or threat model
- **Verbosity avoidance**: Secure patterns (connection pooling, env vars, SSL config) require more code
- **Outdated knowledge**: Many models were trained on patterns predating current best practices (e.g., prior to MySQL 8.0's caching_sha2_password default)

---

## 3. Vulnerable Code Examples

### Example 1: Plaintext Credentials in Connection String (Python + PostgreSQL)

```python
# VULNERABLE - AI-generated
import psycopg2

def get_db_connection():
    return psycopg2.connect(
        "postgresql://postgres:SuperSecretPass!@localhost:5432/mydb"
    )
```

### Example 2: MySQL with Disabled SSL (Node.js)

```javascript
// VULNERABLE - AI-generated
const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'db.example.com',
  user: 'root',
  password: 'root',
  database: 'appdb',
  ssl: false,  // No encryption!
  authSwitchHandler: null
});
// Alternatively via URI:
// mysql://root:root@db.example.com:3306/appdb?useSSL=false&allowPublicKeyRetrieval=true
```

### Example 3: PostgreSQL with sslmode=disable (Go)

```go
// VULNERABLE - AI-generated
import "database/sql"
import _ "github.com/lib/pq"

db, err := sql.Open("postgres",
    "postgres://admin:pass@localhost/mydb?sslmode=disable")
```

### Example 4: Raw SQL Concatenation (Python Flask)

```python
# VULNERABLE - AI-generated SQL injection
@app.route('/search')
def search():
    query = request.args.get('q')
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return cursor.fetchall()
```

### Example 5: Superuser Database User (Django)

```python
# VULNERABLE - AI-generated settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'production',
        'USER': 'postgres',  # SUPERUSER!
        'PASSWORD': 'pass123',
        'HOST': 'localhost',
        'OPTIONS': {
            'sslmode': 'disable',
        }
    }
}
```

### Example 6: Java JDBC with No SSL

```java
// VULNERABLE - AI-generated
String url = "jdbc:mysql://db.example.com:3306/appdb?useSSL=false&allowPublicKeyRetrieval=true";
Connection conn = DriverManager.getConnection(url, "root", "password");
```

---

## 4. Secure Code Fix

### Fix 1: Environment Variables / Secret Manager

```python
# SECURE - Use environment variables
import os
import psycopg2

def get_db_connection():
    return psycopg2.connect(
        host=os.environ['DB_HOST'],
        port=os.environ.get('DB_PORT', '5432'),
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        sslmode='verify-full'
    )
```

For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) instead of environment variables for database credentials.

### Fix 2: SSL/TLS Enforcement

**PostgreSQL:**
```
# Connection string - enforce full verification
postgresql://user:password@host:5432/db?sslmode=verify-full&sslrootcert=/path/to/ca.pem
```

**MySQL (JDBC):**
```java
// SECURE
String url = "jdbc:mysql://db.example.com:3306/appdb?" +
    "useSSL=true&requireSSL=true&verifyServerCertificate=true&" +
    "sslMode=VERIFY_IDENTITY&trustCertificateKeyStoreUrl=file:/path/to/truststore.jks";
```

**MySQL (Node.js):**
```javascript
// SECURE
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync('/path/to/ca-cert.pem'),
    rejectUnauthorized: true
  }
});
```

### Fix 3: Principle of Least Privilege

```sql
-- PostgreSQL - Create dedicated application user with minimal grants

-- 1. Create a dedicated role (not the postgres superuser)
CREATE ROLE app_user WITH LOGIN PASSWORD 'strong-password' NOINHERIT;
GRANT CONNECT ON DATABASE appdb TO app_user;

-- 2. Grant only what's needed on the application schema
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- 3. Deny DDL operations
REVOKE CREATE ON SCHEMA public FROM app_user;

-- 4. Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

-- 5. Set statement timeout
ALTER ROLE app_user SET statement_timeout = '30s';
```

```sql
-- MySQL - Create dedicated application user

CREATE USER 'app_user'@'app-server-ip' IDENTIFIED BY 'strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'app_user'@'app-server-ip';
-- Never grant DROP, ALTER, CREATE, or SUPER privileges
-- Never use 'app_user'@'%' — restrict to specific IP ranges
FLUSH PRIVILEGES;
```

### Fix 4: Connection Pooling with Limits

```python
# SECURE - Using PgBouncer-style pooling (via psycopg2 pool or SQLAlchemy)
from sqlalchemy import create_engine
import os

engine = create_engine(
    f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}"
    f"@{os.environ['DB_HOST']}:{os.environ['DB_PORT']}/{os.environ['DB_NAME']}",
    pool_size=10,           # Max 10 connections in pool
    max_overflow=5,         # Max 5 extra connections beyond pool_size
    pool_timeout=5,         # Wait max 5 seconds for a connection
    pool_recycle=1800,      # Recycle connections after 30 minutes
    connect_args={
        'sslmode': 'verify-full'
    }
)
```

```java
// SECURE - HikariCP connection pool (Java)
HikariConfig config = new HikariConfig();
config.setJdbcUrl("jdbc:postgresql://host/db?sslmode=verify-full");
config.setUsername(System.getenv("DB_USER"));
config.setPassword(System.getenv("DB_PASSWORD"));
config.setMaximumPoolSize(10);
config.setMinimumIdle(3);
config.setConnectionTimeout(5000);       // 5 second timeout
config.setIdleTimeout(300000);           // 5 minute idle max
config.setMaxLifetime(1800000);          // 30 minute max lifetime
config.setConnectionTestQuery("SELECT 1");
```

### Fix 5: Parameterized Queries / ORM Safe Patterns

```python
# SECURE - Parameterized queries
@app.route('/search')
def search():
    query = request.args.get('q')
    cursor.execute(
        "SELECT * FROM products WHERE name LIKE %s",
        (f"%{query}%",)  # Parameterized, NOT string interpolation!
    )
    return cursor.fetchall()
```

```javascript
// SECURE - Parameterized with mysql2
app.get('/search', (req, res) => {
  const query = req.query.q;
  connection.execute(
    'SELECT * FROM products WHERE name LIKE ?',
    [`%${query}%`],  // Placeholder, not concatenation
    (err, results) => res.json(results)
  );
});
```

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

## 6. Real CVEs (Web-Verified from NVD)

### CVE-2024-10979 — PostgreSQL PL/Perl Environment Variable Hijacking
- **CVSS 3.1:** 8.8 (HIGH)
- **Published:** 2024-11-14
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-10979
- **Description:** Incorrect control of environment variables in PostgreSQL PL/Perl allows an unprivileged database user to change sensitive process environment variables (e.g., PATH). This often suffices to enable arbitrary code execution, even if the attacker lacks a database server operating system user. Affects versions before 17.1, 16.5, 15.9, 14.14, 13.17, and 12.21.
- **CWE:** CWE-15 (External Control of System or Configuration Setting), CWE-610 (Externally Controlled Reference)
- **Relevance to AI-Generated Apps:** AI models frequently enable PL/Perl or PL/Python for "data processing" without understanding the security boundary implications.

### CVE-2024-7348 — PostgreSQL pg_dump TOCTOU Race Condition
- **CVSS 3.1:** 8.8 (HIGH) / 7.5 (HIGH)
- **Published:** 2024-08-08
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-7348
- **Description:** Time-of-check Time-of-use (TOCTOU) race condition in pg_dump allows an object creator to execute arbitrary SQL functions as the user running pg_dump, which is often a superuser. Affects versions before 16.4, 15.8, 14.13, 13.16, and 12.20.
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Relevance to AI-Generated Apps:** AI-generated backup scripts often run pg_dump as superuser, and the generated code may not follow least-privilege backup practices.

### CVE-2024-32655 — Npgsql (PostgreSQL .NET Provider) Integer Overflow → SQL Injection
- **CVSS 3.1:** 8.1 (HIGH)
- **Published:** 2024-05-14
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-32655
- **Description:** Integer overflow in Npgsql's `WriteBind()` method allows attackers to inject arbitrary PostgreSQL protocol messages, leading to execution of arbitrary SQL statements. Fixed in versions 4.0.14, 4.1.13, 5.0.18, 6.0.11, 7.0.7, and 8.0.3.
- **CWE:** CWE-89 (SQL Injection), CWE-190 (Integer Overflow)
- **Relevance to AI-Generated Apps:** AI-generated .NET applications often use Npgsql without checking version or applying security patches. A model trained before mid-2024 would not know about this vulnerability.

### CVE-2024-36039 — PyMySQL SQL Injection via Untrusted JSON
- **CVSS 3.1:** 6.3 (MEDIUM)
- **Published:** 2024-05-21
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-36039
- **Description:** PyMySQL through version 1.1.0 allows SQL injection if used with untrusted JSON input because keys are not escaped by `escape_dict`. Fixed in version 1.1.1.
- **CWE:** CWE-89 (SQL Injection)
- **Relevance to AI-Generated Apps:** AI-generated Python code commonly uses `escape_dict()` (or the MySQL `escape()` function) from PyMySQL incorrectly, believing it sanitizes input when it does not.

### CVE-2024-5753 — Vanna AI SQL Injection (AI-Generated SQL Context)
- **CVSS 3.0:** 7.5 (HIGH)
- **Published:** 2024-07-05
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-5753
- **Description:** Vanna AI (text-to-SQL library) version v0.3.4 is vulnerable to SQL injection via `pg_read_file()`, allowing unauthenticated remote attackers to read arbitrary local files.
- **CWE:** CWE-89 (SQL Injection)
- **Relevance to AI-Generated Apps:** This CVE directly demonstrates the risk of AI-generated SQL queries — the text-to-SQL pipeline itself becomes an injection vector. Applications that use LLMs to generate SQL must treat the output as untrusted.

### CVE-2024-5565 — Vanna AI Prompt Injection Leading to RCE
- **CVSS 3.1:** 8.1 (HIGH)
- **Published:** 2024-05-31
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-5565
- **Description:** The Vanna AI library allows prompt injection to run arbitrary Python code instead of intended visualization code. External input to the "ask" method with `visualize=True` leads to remote code execution.
- **CWE:** CWE-94 (Code Injection)
- **Relevance to AI-Generated Apps:** Demonstrates how text-to-SQL pipelines compound risk — SQL injection + code injection in a single AI-generated tool.

### CVE-2024-20960 — MySQL Server
- **CVSS 3.1:** 6.5 (MEDIUM) — NVD (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H, availability-only DoS)
- **Published:** 2024-04-16 (Oracle CPU)
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-20960
- **Description:** Easily exploitable vulnerability allows low-privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- **Relevance to AI-Generated Apps:** AI-generated applications frequently use older MySQL connectors and may miss critical patch levels.

---

## 7. Prevention Checklist

- [ ] **Never hardcode credentials** — use environment variables, secrets managers, or vault services
- [ ] **Enforce SSL/TLS** — set `sslmode=verify-full` (PostgreSQL) or `useSSL=true&verifyServerCertificate=true` (MySQL)
- [ ] **Use dedicated application users** — never use `postgres` superuser or MySQL `root` for application connections
- [ ] **Apply least privilege** — grant only SELECT, INSERT, UPDATE, DELETE on specific tables; never grant DDL
- [ ] **Restrict network access** — bind to private IPs only, use security groups/firewall rules
- [ ] **Implement connection pooling** — use PgBouncer, HikariCP, or SQLAlchemy pool with size limits
- [ ] **Set statement timeouts** — prevent runaway queries: `statement_timeout=30s` (PostgreSQL), `max_execution_time=30000` (MySQL)
- [ ] **Use parameterized queries** — never use string formatting/f-strings for SQL — always use placeholders (`%s`, `?`, `:param`)
- [ ] **Run `mysql_secure_installation`** — mandatory for any MySQL deployment
- [ ] **Enable audit logging** — pgaudit for PostgreSQL, audit_log plugin for MySQL
- [ ] **Keep versions updated** — subscribe to PostgreSQL and MySQL security announcements
- [ ] **Scan dependencies** — check for known CVEs in database drivers (psycopg2, PyMySQL, mysql2, Npgsql, etc.)
- [ ] **Use password rotation** — rotate database passwords at least every 90 days
- [ ] **Set `idle_in_transaction_session_timeout`** — prevents abandoned transactions holding locks
- [ ] **Enable row-level security** — for multi-tenant applications

---

## 8. Vibe-Coding Red Flags

- [ ] **Connection string in config files** — the `.env` file committed to GitHub with `DATABASE_URL=postgresql://user:pass@host/db`
- [ ] **`sslmode=disable` or `useSSL=false`** — any AI-generated code that disables encryption
- [ ] **`allowPublicKeyRetrieval=true`** — almost always a sign the AI was debugging a connection error and disabled security
- [ ] **`GRANT ALL PRIVILEGES`** — the model defaulting to superuser access
- [ ] **String formatting in SQL queries** — `f"SELECT ... WHERE x = '{input}'"` or `"SELECT ... WHERE x = " + input`
- [ ] **No `.env.example` with DB_HOST/DB_USER/DB_PASS** — hardcoded values are worse
- [ ] **Docker Compose without database password** — `POSTGRES_PASSWORD: postgres` or `MYSQL_ROOT_PASSWORD: root`
- [ ] **Exposed database ports** — `ports: - "5432:5432"` or `ports: - "3306:3306"` without any firewall
- [ ] **No health check or connection validation** — missing `SELECT 1` ping in connection pool config
- [ ] **Generic `mysql2` / `psycopg2` without SSL options** — AI assumes defaults are safe
- [ ] **Database migrated via `root`** — any AI-generated migration script using admin credentials
- [ ] **No connection timeout configuration** — AI leaves default (infinite) timeouts
- [ ] **Database user from `@'%'`** — MySQL user created with access from any host
- [ ] **`postgres.conf` or `my.cnf` with `listen_addresses = '*'`** — binds to all interfaces
- [ ] **Text-to-SQL libraries without input sanitization** — Vanna AI-style libraries that execute generated SQL without validation

---

## 9. References

- **PostgreSQL Security Documentation:** https://www.postgresql.org/docs/current/security.html
- **PostgreSQL Security Vulnerabilities:** https://www.postgresql.org/support/security/
- **MySQL Security Guide:** https://dev.mysql.com/doc/refman/8.0/en/security.html
- **MySQL Security Vulnerabilities:** https://www.oracle.com/security-alerts/
- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP NoSQL Injection:** https://owasp.org/www-community/attacks/NoSQL_Injection
- **NVD CVE Database:** https://nvd.nist.gov/
- **CWE-798 (Hardcoded Credentials):** https://cwe.mitre.org/data/definitions/798.html
- **CWE-311 (Missing Encryption):** https://cwe.mitre.org/data/definitions/311.html
- **PostgreSQL Row-Level Security:** https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- **MySQL Enterprise Audit:** https://dev.mysql.com/doc/refman/8.0/en/audit-log.html
- **Cloud Security Alliance — Vibe Coding's Security Debt (2026):** https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/
