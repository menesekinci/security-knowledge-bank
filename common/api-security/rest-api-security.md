# REST API Security

> **Category:** Common / API Security
> **Last Updated:** July 2026

## Overview

REST APIs are the backbone of modern web and mobile applications. This document covers authentication methods, rate limiting, pagination security, HATEOAS risks, and related CVEs with vulnerable and secure code examples.

---

## Table of Contents

1. [Authentication Methods (JWT, OAuth2, API Keys)](#1-authentication-methods)
2. [Rate Limiting](#2-rate-limiting)
3. [Pagination Security](#3-pagination-security)
4. [HATEOAS Risks](#4-hateoas-risks)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

---

## 1. Authentication Methods

### 1.1 JWT (JSON Web Tokens)

JWTs are stateless tokens consisting of Header, Payload, and Signature. Common vulnerabilities:

| Vulnerability | Description |
|---|---|
| **`alg: none` Attack** | Attacker sets `"alg": "none"` in the header to bypass signature verification |
| **Algorithm Confusion** | Switches RS256 (asymmetric) to HS256 (symmetric), using the public key as the HMAC secret |
| **Weak Secret Key** | Brute-forceable HMAC secret allows arbitrary token forgery |
| **Expired Token Reuse** | Missing or improperly validated `exp` claim |
| **Sensitive Data in Payload** | Base64-encoded (not encrypted) payload leaks PII |

#### Vulnerable Code (JWT — Node.js/Express)

```javascript
// VULNERABLE: Uses jwt.decode() instead of jwt.verify()
const token = req.headers.authorization.split(' ')[1];
const decoded = jwt.decode(token); // No signature verification!
req.user = decoded;
```

#### Secure Code (JWT — Node.js/Express)

```javascript
// SECURE: Uses jwt.verify() with a strong secret
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'], // Explicit algorithm whitelist
    issuer: 'my-api',
    audience: 'my-app'
  }, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
```

### 1.2 OAuth2

OAuth2 is an authorization framework. Common implementation flaws:

- **CSRF on authorization code flow** — missing `state` parameter
- **Redirect URI validation bypass** — open redirect in callback
- **Token leakage via Referer header** — authorization code in browser history
- **Improper scope validation** — privilege escalation through scope manipulation

#### Vulnerable Code (OAuth2 — Python/Flask)

```python
# VULNERABLE: Missing state parameter — CSRF attack possible
@app.route('/callback')
def oauth_callback():
    code = request.args.get('code')
    token = exchange_code_for_token(code)  # No CSRF check
    session['token'] = token
    return redirect('/dashboard')
```

#### Secure Code (OAuth2 — Python/Flask)

```python
# SECURE: State parameter validated against session
import secrets

@app.route('/login/oauth')
def oauth_login():
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    return redirect(f'https://auth.provider.com/authorize?client_id=...&state={state}')

@app.route('/callback')
def oauth_callback():
    if request.args.get('state') != session.get('oauth_state'):
        abort(403)  # CSRF detected!
    code = request.args.get('code')
    token = exchange_code_for_token(code)
    session['token'] = token
    session.pop('oauth_state', None)
    return redirect('/dashboard')
```

### 1.3 API Keys

API keys are the simplest but most frequently mishandled authentication method.

- **Hardcoded keys** in source code, config files, mobile apps
- **Key leakage via URL** (GET parameters logged by proxies)
- **No key rotation** — compromised keys remain active indefinitely
- **Overprivileged keys** — single key with full admin access

#### Vulnerable Code (API Key)

```python
# VULNERABLE: API key hardcoded and sent as URL parameter
API_KEY = "sk-live-abc123def456"  # Hardcoded in source code!

response = requests.get(
    f"https://api.example.com/users?api_key={API_KEY}"  # Leaked in logs!
)
```

#### Secure Code (API Key)

```python
# SECURE: Key from environment, sent via header
import os
import hmac

API_KEY = os.environ.get("API_KEY")  # Never hardcoded

response = requests.get(
    "https://api.example.com/users",
    headers={
        "X-API-Key": API_KEY,  # Header, not URL
        "User-Agent": "my-service/1.0"
    }
)
```

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

## 3. Pagination Security

Pagination vulnerabilities can expose data through:

- **Mass Assignment** — manipulating `limit`/`offset` to extract all records
- **Cursor-based IDOR** — guessing/iterating sequential cursors
- **Timing Attacks** — inferring data existence through response timing
- **Sort Injection** — manipulating sort parameters for SQL injection

### Vulnerable Code (Unbounded Pagination)

```python
# VULNERABLE: Unbounded pagination — attacker can dump entire DB
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)  # No max bound!
    
    users = db.execute(
        "SELECT id, email, name FROM users LIMIT ? OFFSET ?",
        (limit, (page - 1) * limit)
    ).fetchall()
    
    return jsonify(users)
```

### Secure Code (Bounded Pagination)

```python
# SECURE: Bounded pagination with max limit and authorization check
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    limit = min(request.args.get('limit', 50, type=int), 100)  # Hard cap
    
    if page < 1 or limit < 1:
        return jsonify(error="Invalid pagination params"), 400
    
    # Authorization: only return users the caller is allowed to see
    if not current_user.can_view_users():
        return jsonify(error="Insufficient permissions"), 403
    
    users = db.execute(
        "SELECT id, email, name FROM users LIMIT ? OFFSET ?",
        (limit, (page - 1) * limit)
    ).fetchall()
    
    # Return total count for transparency (but rate-limit this endpoint)
    total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    return jsonify({
        "data": users,
        "page": page,
        "limit": limit,
        "total": total
    })
```

---

## 4. HATEOAS Risks

HATEOAS (Hypermedia as the Engine of Application State) embeds links in API responses. Risks include:

- **Link injection** — attacker-controlled URLs in responses leading to phishing
- **Dynamic link generation** — path traversal or SSRF via link templates
- **Excessive information disclosure** — exposing admin-only endpoints via links
- **Insecure link templating** — template injection in URL patterns

### Vulnerable Code (HATEOAS — Dynamic Link Injection)

```java
// VULNERABLE: Using user input directly in HATEOAS links
// User-controlled "nextUrl" parameter embedded in response links
@GetMapping("/api/orders/{id}")
public EntityModel<Order> getOrder(@PathVariable Long id,
                                    @RequestParam String baseUrl) {
    Order order = orderService.findById(id);
    EntityModel<Order> model = EntityModel.of(order);
    
    // Attacker can inject malicious URLs!
    model.add(Link.of(baseUrl + "/orders/" + id + "/pay", "payment"));
    
    return model;
}
```

### Secure Code (HATEOAS — Whitelist Link Sources)

```java
// SECURE: Use configured base URL, never user input
@GetMapping("/api/orders/{id}")
public EntityModel<Order> getOrder(@PathVariable Long id) {
    Order order = orderService.findById(id);
    EntityModel<Order> model = EntityModel.of(order);
    
    // Use only server-configured link builder
    model.add(linkTo(methodOn(OrderController.class).payOrder(id)).withRel("payment"));
    model.add(linkTo(methodOn(OrderController.class).getOrder(id)).withSelfRel());
    
    // Conditional links based on actual authorization
    if (currentUser.canCancel(order)) {
        model.add(linkTo(methodOn(OrderController.class).cancelOrder(id)).withRel("cancel"));
    }
    
    return model;
}
```

---

## 5. CVEs & Real-World Examples

### CVE-2022-23540 — jsonwebtoken Signature Validation Bypass
- **Description**: In `jsonwebtoken` `<= 8.5.1`, calling `jwt.verify()` without specifying `algorithms` and with a falsy secret/key defaults to the `none` algorithm, so an unsigned/tampered token is accepted — a signature-validation bypass leading to auth bypass or privilege escalation.
- **Affected**: jsonwebtoken (npm) <= 8.5.1
- **CVSS**: 7.6 (High)
- **Fix**: Upgrade to jsonwebtoken 9.0.0+ (drops default `none` support); always pass an explicit `algorithms` allowlist and a strong secret
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2022-23540

### CVE-2025-45768 — PyJWT Weak Encryption (DISPUTED)
- **Description**: A reported weak-encryption issue in PyJWT v2.10.1 (CWE-311). **Disputed by the supplier**: the key length is chosen by the application using the library, so the maintainers consider key strength an application-level responsibility rather than a library flaw.
- **Affected**: PyJWT 2.10.1 (disputed)
- **CVSS**: Not authoritatively scored (entry is disputed)
- **Fix**: No official patch — this is disputed; applications should enforce sufficiently strong keys themselves
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-45768

### CVE-2025-8625 — Hard-coded JWT Secret in WordPress REST API
- **Description**: CopyPress REST API plugin uses a hard-coded JWT signing key when no secret is set, allowing unauthenticated attackers to forge tokens
- **Affected**: CopyPress REST API 1.1 - 1.2 (WordPress)
- **CVSS**: 9.8 (Critical)
- **Fix**: Require administrators to set a unique secret key; never fall back to hardcoded values
- **Source**: https://github.com/Nxploited/CVE-2025-8625

### CVE-2024-47654 — Missing Rate Limiting on OTP API
- **Description**: Shilpi Client Dashboard lacks rate limiting and CAPTCHA protection for OTP requests, enabling unlimited brute-force
- **Affected**: Shilpi Client Dashboard (various versions)
- **CVSS**: 7.5 (High)
- **Fix**: Implement per-IP and per-account rate limiting with CAPTCHA after N attempts
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2024-47654

### CVE-2025-54576 — OAuth2-Proxy Authentication Bypass
- **Description**: Critical auth bypass in OAuth2-Proxy when `skip_auth_routes` is misconfigured, allowing unauthenticated access to protected routes
- **Affected**: OAuth2-Proxy (specific versions)
- **CVSS**: 9.1 (Critical)
- **Fix**: Proper validation of `skip_auth_routes` configuration; restrict to non-sensitive endpoints only
- **Source**: https://zeropath.com/blog/cve-2025-54576-oauth2-proxy-auth-bypass

### CVE-2025-27371 — OAuth 2.0 JWT Profile Ambiguity
- **Description**: Ambiguities in the JSON Web Token Profile for OAuth 2.0 Client Authentication mechanism allowing token confusion
- **Affected**: IETF OAuth 2.0 specifications and implementations
- **CVSS**: 6.9 (Medium)
- **Fix**: Implement explicit token type checking and audience validation
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-27371

---

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT.io](https://jwt.io/)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://datatracker.ietf.org/doc/rfc9700/)
- [PortSwigger Web Security Academy — JWT Attacks](https://portswigger.net/web-security/jwt)
- [AHNLAB ASEC — The Shadow of JWT-Based Authentication](https://asec.ahnlab.com/en/91676/)
- [Vaadata — JWT Vulnerabilities & Best Practices](https://www.vaadata.com/en/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/)
