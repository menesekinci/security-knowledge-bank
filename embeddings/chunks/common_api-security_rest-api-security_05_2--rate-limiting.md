---
source: "common/api-security/rest-api-security.md"
title: "REST API Security"
heading: "2. Rate Limiting"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, authentication, limiting, methods, overview, pagination, rate, security, table]
chunk: 5/9
---

## 2. Rate Limiting

Missing or inadequate rate limiting enables brute-force attacks, credential stuffing, and DoS. OWASP API Security Top 10 lists this as **API4:2019 — Lack of Resources & Rate Limiting** and **API6:2023 — Unrestricted Access to Sensitive Business Flows**.

### Vulnerable Code (No Rate Limiting)

```python
# VULNERABLE: No rate limiting on login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = authenticate(username, password)
    if user:
        return jsonify(token=create_token(user))
    return jsonify(error="Invalid credentials"), 401
```

### Secure Code (Rate Limited)

```python
# SECURE: Rate limiting with Redis-based sliding window
import redis
import time

r = redis.Redis(host='localhost', port=6379, db=0)

def is_rate_limited(client_ip, endpoint, max_requests=10, window_seconds=60):
    key = f"ratelimit:{endpoint}:{client_ip}"
    current = r.get(key)
    
    if current and int(current) >= max_requests:
        return True
    
    pipe = r.pipeline()
    pipe.incr(key, 1)
    pipe.expire(key, window_seconds)
    pipe.execute()
    return False

@app.route('/api/login', methods=['POST'])
def login():
    client_ip = request.remote_addr
    
    if is_rate_limited(client_ip, 'login', max_requests=5, window_seconds=300):
        return jsonify(error="Too many attempts. Try again later."), 429
    
    username = request.json.get('username')
    password = request.json.get('password')
    user = authenticate(username, password)
    if user:
        return jsonify(token=create_token(user))
    return jsonify(error="Invalid credentials"), 401
```

---