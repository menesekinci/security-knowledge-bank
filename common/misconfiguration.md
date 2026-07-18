# Security Misconfiguration

**CWE:** CWE-16 (Configuration), CWE-611 (Improper XML Parsing), CWE-942 (Permissive Cross-domain Policy)
**OWASP Top 10:2021:** A05 — Security Misconfiguration
**OWASP Top 10:2025:** A02 — Security Misconfiguration (moved up)

---

## What Is Security Misconfiguration?

Security misconfiguration occurs when security settings are **not defined, implemented, or maintained** properly. This includes default credentials, unnecessary features enabled, overly permissive CORS, verbose error messages, unsecured cloud storage, and missing security headers.

## Why Vibe Coding Makes This Worse

- **AI generates debug configurations:** `DEBUG=True`, `NODE_ENV=development` left in production
- **AI uses framework defaults:** Many frameworks ship with insecure defaults (e.g., default admin passwords)
- **AI doesn't set security headers:** Generated apps often lack CSP, HSTS, X-Frame-Options
- **AI generates permissive CORS:** `Access-Control-Allow-Origin: *` for everything
- **Hardcoded config values:** `DB_HOST=localhost`, `ADMIN_PASSWORD=admin` scattered through generated code

## Common Misconfigurations

### 1. Debug Mode Enabled in Production

```python
# 🔴 VULNERABLE: debug mode in production
app.run(debug=True)
# Exposes: stack traces, interactive debugger, source code
```

```javascript
// 🔴 VULNERABLE: dev mode
const isDev = true;  // Should be process.env.NODE_ENV === 'production'
process.env.NODE_ENV = 'development';
```

### 2. Default Credentials

```yaml
# 🔴 VULNERABLE: default credentials
services:
  postgres:
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres  # NEVER use defaults
  redis:
    # No password at all!
```

### 3. Permissive CORS

```javascript
// 🔴 VULNERABLE: allows any origin
app.use(cors({ origin: '*' }));
app.use(cors());  // Same — defaults to '*'
```

```python
# 🔴 VULNERABLE
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
```

### 4. Missing Security Headers

```python
# 🔴 VULNERABLE: minimal headers
response = make_response(render_template('page.html'))
# Missing:
# Content-Security-Policy
# Strict-Transport-Security
# X-Content-Type-Options
# X-Frame-Options
```

### 5. Unrestricted File Uploads

```python
# 🔴 VULNERABLE: no file type validation
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')
```

## Fixed Configurations

### Secure CORS
```javascript
// ✅ SECURE: specific origins
const allowedOrigins = ['https://app.mycompany.com', 'https://admin.mycompany.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
}));
```

### Secure Headers (Helmet.js)
```javascript
// ✅ SECURE: use security header middleware
const helmet = require('helmet');
app.use(helmet());
// Sets: X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.
```

### Secure File Uploads
```python
import os
import magic  # libmagic binding

ALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}
UPLOAD_DIR = '/secure/uploads'

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    # ✅ Validate file type by content (not extension)
    mime = magic.from_buffer(file.read(2048), mime=True)
    if mime not in ALLOWED_TYPES:
        return 'Invalid file type', 400

    # ✅ Use safe filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_DIR, filename))
```

### Production-Ready Config
```python
# ✅ SECURE: environment-based config
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
```

---

## Security Headers Checklist

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Prevents XSS and data injection |
| `Strict-Transport-Security` | Enforces HTTPS |
| `X-Content-Type-Options: nosniff` | Prevents MIME sniffing |
| `X-Frame-Options: DENY` | Prevents clickjacking |
| `Referrer-Policy` | Controls referrer info leakage |
| `Permissions-Policy` | Restricts browser feature access |
| `Cross-Origin-Embedder-Policy` | COEP for cross-origin isolation |

---

## Prevention Checklist for AI Prompts

```
✅ CONFIGURATION REQUIREMENTS:
- Use environment variables for ALL secrets and config values
- Never hardcode credentials, even in sample code or comments
- Set NODE_ENV=production / DEBUG=False / APP_ENV=production
- Enable all security middleware (Helmet, Django security middleware)
- Configure CORS with explicit allowlist, never wildcard
- Validate file uploads by content type (not extension)
- Remove default accounts or change credentials immediately
- Disable unnecessary HTTP methods (TRACE, PUT, DELETE if unused)
- Set restrictive security headers
- Use HTTPS only with HSTS
- Keep software/frameworks updated
- Scan infrastructure with tools like ScoutSuite (cloud) or Lynis (Linux)
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Kibana Console arbitrary code execution | CVE-2018-17246 | Local file inclusion / RCE via the Console plugin (Kibana < 6.4.3 / < 5.6.13) |
| MongoDB no auth by default | N/A (misconfiguration, no CVE) | Massive ransomware attacks against internet-exposed, auth-less instances |
| Apache Struts dev mode | CVE-2017-5638 | RCE (Equifax breach) |
| Kubernetes Dashboard auth bypass | CVE-2018-18264 | Reads cluster secrets via the Dashboard service account (Dashboard < 1.10.1) |

---

## References

- [OWASP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/)
- [Security Headers Analyzer](https://securityheaders.com/)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
