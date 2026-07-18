---
source: "common/api-security/rest-api-security.md"
title: "REST API Security"
heading: "1. Authentication Methods"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, authentication, limiting, methods, overview, pagination, rate, security, table]
chunk: 4/9
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