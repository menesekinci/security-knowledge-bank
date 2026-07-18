---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Common Misconfigurations"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 4/9
---

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