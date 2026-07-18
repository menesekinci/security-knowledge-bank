---
source: "languages/javascript/jwt-misuse.md"
title: "🔴 JWT Authentication Pitfalls (Node.js/JS)"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [common, javascript, language-vuln, most, prevention]
---

# 🔴 JWT Authentication Pitfalls (Node.js/JS)

## Most Common Mistakes

### 1. alg:none Attack
```javascript
// 💀 VULNERABLE:
const jwt = require('jsonwebtoken');
const decoded = jwt.decode(token);  // decode() does NOT verify!

// ✅ SECURE:
const decoded = jwt.verify(token, SECRET_KEY);  // verify() checks the signature!
```

An attacker sends an unsigned token with `{"alg":"none","typ":"JWT"}` → if `verify()` isn't used, it gets accepted.

### 2. Weak Secret
```javascript
// 💀 VULNERABLE:
const token = jwt.sign({user: "admin"}, "secret123");  // weak secret!

// ✅ SECURE:
const crypto = require('crypto');
const SECRET = crypto.randomBytes(64).toString('hex');
const token = jwt.sign({user: "admin"}, SECRET, {expiresIn: '1h'});
```

### 3. Algorithm Confusion (RS256 → HS256)
```javascript
// 💀 VULNERABLE:
jwt.verify(token, publicKey);  // Can use public key as HMAC secret!

// ✅ SECURE:
jwt.verify(token, publicKey, {algorithms: ['RS256']});  // Pin the algorithm!
```

## Prevention
- Don't use `jwt.decode()` → use `jwt.verify()`
- Use strong secret (256+ bit random)
- Use algorithm whitelist (`algorithms: ['HS256']`)
- Make `expiresIn` mandatory
- Validate `issuer` and `audience`

---

**Severity: 🔴 Critical** — Auth bypass.
