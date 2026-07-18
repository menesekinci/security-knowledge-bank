---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "3. Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 4/10
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