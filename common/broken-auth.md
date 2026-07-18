# Broken Authentication & Session Management

**CWE Categories:** CWE-287 (Improper Authentication), CWE-862 (Missing Authorization), CWE-352 (CSRF), CWE-307 (Improper Restriction of Authentication Attempts)
**OWASP Top 10:2021:** A07 — Identification and Authentication Failures
**CWE Top 25 2024:** #4 (CSRF), #9 (Missing Authorization), #14 (Improper Authentication)

---

## What Is Broken Authentication?

Broken Authentication encompasses vulnerabilities that allow attackers to **bypass, forge, or steal** authentication credentials and session tokens. This includes weak password policies, session fixation, session hijacking, credential stuffing, JWT flaws, and inadequate lockout mechanisms.

**The impact:** An attacker can impersonate legitimate users, escalate privileges, access sensitive data, and perform actions as the victim.

## Why Vibe Coding Makes This Worse

AI-generated authentication code frequently contains subtle but critical flaws:

- **AI reimplements auth from scratch:** Instead of using battle-tested libraries, AI generates custom session management with homebrew tokens
- **JWT secrets hardcoded or weak:** AI places `jwt_secret = "secret"` in the code
- **Session tokens in URLs:** AI uses query parameters for session IDs
- **No rate limiting on login:** AI forgets to add lockout mechanisms
- **Insecure password storage:** AI uses MD5/SHA1 for passwords (see crypto.md)
- **Missing CSRF tokens:** AI generates forms without CSRF protection
- **"Remember me" done wrong:** AI implements persistent tokens without rotation

---

## Common Vulnerabilities

### 1. Weak Password Policies

**Vulnerable Code — Node.js (Express)**
```javascript
const users = []; // In-memory (also bad, but besides the point)

app.post('/register', (req, res) => {
    // 🔴 VULNERABLE: no password strength requirements
    const { username, password } = req.body;
    users.push({ username, password: md5(password) }); // Double bad
    res.send('Registered!');
});
```

**Fixed Code**
```javascript
const bcrypt = require('bcrypt');
const zxcvbn = require('zxcvbn');

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // ✅ Check password strength
    const strength = zxcvbn(password);
    if (strength.score < 3) {
        return res.status(400).json({
            error: 'Password too weak',
            suggestions: strength.feedback.suggestions
        });
    }

    // ✅ Hash with bcrypt (cost factor 12)
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);

    // Store hash, not the password
    await db.users.create({ username, passwordHash: hash });
    res.send('Registered!');
});
```

### 2. Credential Stuffing / Brute Force

**Vulnerable**
```javascript
app.post('/login', async (req, res) => {
    // 🔴 VULNERABLE: no rate limiting
    const { username, password } = req.body;
    const user = await db.users.findOne({ username });
    if (user && await bcrypt.compare(password, user.passwordHash)) {
        req.session.userId = user.id;
        res.send('Logged in!');
    } else {
        res.status(401).send('Invalid credentials');
    }
});
```

**Fixed**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 5,                      // 5 attempts per window
    message: 'Too many attempts, try again later',
    standardHeaders: true,
    legacyHeaders: false
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = await db.users.findOne({ username });

    if (!user) {
        // ✅ Use same response time regardless of user existence
        await bcrypt.compare('dummy', '$2b$12$...');
        return res.status(401).send('Invalid credentials');
    }

    if (await bcrypt.compare(password, user.passwordHash)) {
        // ✅ Regenerate session on login
        req.session.regenerate(() => {
            req.session.userId = user.id;
            res.send('Logged in!');
        });
    } else {
        res.status(401).send('Invalid credentials');
    }
});
```

### 3. Session Fixation & Hijacking

**Vulnerable**
```javascript
// 🔴 VULNERABLE: session ID before login is reused after login
app.post('/login', async (req, res) => {
    const user = await authenticate(req.body);
    req.session.userId = user.id;  // Session ID stays the same!
    res.send('Logged in!');
});

// 🔴 VULNERABLE: session in URL
// After login, redirects to: /dashboard?session=abc123
```

**Fixed**
```javascript
app.post('/login', async (req, res) => {
    const user = await authenticate(req.body);
    if (user) {
        // ✅ Regenerate session ID on privilege escalation
        req.session.regenerate(() => {
            req.session.userId = user.id;
            // Set session expiry
            req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 24h
            req.session.cookie.httpOnly = true;
            req.session.cookie.secure = true;
            req.session.cookie.sameSite = 'strict';
            res.send('Logged in!');
        });
    }
});
```

### 4. JWT Pitfalls

**Vulnerable JWT Patterns**
```javascript
const jwt = require('jsonwebtoken');

// 🔴 VULNERABLE: algorithm confusion (accepts 'none')
const token = req.headers.authorization?.split(' ')[1];
const decoded = jwt.decode(token); // Does NOT verify signature!

// 🔴 VULNERABLE: no expiration
const token = jwt.sign({ userId: 123 }, 'secret'); // Never expires

// 🔴 VULNERABLE: secret in code
const JWT_SECRET = 'myapp';  // Too short, predictable

// 🔴 VULNERABLE: using weak algorithm
const token = jwt.sign({ userId: 123 }, 'secret', { algorithm: 'HS256' }); // HS256 < HS384 < HS512
```

**Fixed JWT Patterns**
```javascript
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// ✅ SECURE: strong secret from environment
const JWT_SECRET = process.env.JWT_SECRET; // Min 256 bits (32 chars)

// ✅ SECURE: proper token creation
function createAccessToken(user) {
    return jwt.sign(
        {
            sub: user.id,
            role: user.role,
            jti: uuidv4(),             // Unique token ID
            iat: Math.floor(Date.now() / 1000),
        },
        JWT_SECRET,
        {
            algorithm: 'HS512',
            expiresIn: '15m',           // Short-lived access token
            issuer: 'myapp',
            audience: 'myapp-users',
        }
    );
}

// ✅ SECURE: proper verification
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS512'],       // Explicit algorithm allowlist
            issuer: 'myapp',
            audience: 'myapp-users',
        });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            // Redirect to refresh endpoint gracefully
            return null;
        }
        throw err;
    }
}
```

### 5. CSRF (Cross-Site Request Forgery)

**Vulnerable**
```html
<!-- 🔴 VULNERABLE: no CSRF token -->
<form action="/transfer" method="POST">
    <input name="amount" value="1000">
    <input name="to" value="attacker">
    <button>Send</button>
</form>
<!-- Attacker's site embeds: <img src="https://bank.com/transfer?amount=1000&to=attacker"> -->
```

**Fixed**
```javascript
// ✅ Generate CSRF token per session
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

app.get('/transfer', (req, res) => {
    res.render('transfer', { csrfToken: req.csrfToken() });
});

app.post('/transfer', (req, res) => {
    // csurf middleware validates the token automatically
    // If invalid → throws "invalid csrf token" error
    processTransfer(req.body);
});
```

---

## Prevention Checklist for AI Prompts

```
✅ AUTHENTICATION REQUIREMENTS FOR THIS CODE:
- Use a well-known authentication library (Passport.js, Devise, Spring Security, django-allauth)
- Hash passwords with bcrypt (cost ≥ 12), Argon2id, or scrypt
- NEVER store passwords in plaintext, MD5, SHA1, or unsalted hashes
- NEVER hardcode secrets, API keys, or JWT secrets — use environment variables
- JWT secrets must be ≥ 256 bits and rotated regularly
- JWT tokens must have expiration (access: 15min, refresh: 7d max)
- Disable JWT 'none' algorithm — explicitly specify allowed algorithms
- Implement rate limiting on login endpoints (5 attempts per 15 min)
- Regenerate session ID on login and privilege escalation
- Set HttpOnly, Secure, SameSite=Strict on cookies
- Implement CSRF protection for all state-changing operations
- Use secure session storage (Redis, database), not in-memory
- Never expose session tokens in URLs
- Implement multi-factor authentication for sensitive operations
```

### Session Security Checklist

| Measure | Required? |
|---|---|
| HttpOnly cookie flag | ✅ Always |
| Secure cookie flag | ✅ Always (production) |
| SameSite=Strict/Lax | ✅ Always |
| Session timeout (idle + absolute) | ✅ Always |
| Session regeneration on login | ✅ Always |
| CSRF tokens on all forms | ✅ Always |
| Rate limiting on auth endpoints | ✅ Always |
| Account lockout after N failures | ✅ Always |
| Password strength enforcement | ✅ Always |

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| JWT algorithm confusion / `alg:none` (jsonwebtoken) | CVE-2015-9235 | Signature accepted from token header → forged tokens (public key as HMAC secret) |
| Apache Tomcat session-persistence deserialization | CVE-2020-9484 | RCE via `PersistenceManager` + `FileStore` deserialization (not session fixation) |
| Drupal Form API property injection (Drupalgeddon2) | CVE-2018-7600 | Unauthenticated remote code execution (CVSS 9.8) |
| Spring Security WebFlux `**` pattern mismatch | CVE-2023-34034 | Authorization bypass — security rules skipped (not a JWT flaw) |
| Hard-coded JWT secret (MICROSENS NMP Web+) | CVE-2025-49151 | Unauthenticated JWT forgery → authentication bypass (CVSS 9.1) |
| Pulse Connect Secure VPN arbitrary file read | CVE-2019-11510 | Unauthenticated leak of session tokens & plaintext credentials (CVSS 10.0), mass-exploited |

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [JWT.io — Debugger & Best Practices](https://jwt.io/)
- [Auth0 — JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
