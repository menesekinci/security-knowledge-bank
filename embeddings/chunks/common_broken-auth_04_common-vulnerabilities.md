---
source: "common/broken-auth.md"
title: "Broken Authentication & Session Management"
heading: "Common Vulnerabilities"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common, common-vuln, cves, prevention, real-world, vibe, vulnerabilities, what]
chunk: 4/7
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