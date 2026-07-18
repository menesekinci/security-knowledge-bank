---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "4. Secure Code Fix"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 5/10
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