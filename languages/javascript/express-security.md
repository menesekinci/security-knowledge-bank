# Express / Fastify Security Deep Dive

> **Category:** JavaScript / Express & Fastify Security Knowledge Bank  
> **Focus:** Middleware ordering, helmet, rate limiting, session security, URL normalization gaps  
> **Last Updated:** July 2026

---

## Overview

Express.js and Fastify are the two most popular Node.js web frameworks. Both are vulnerable to middleware ordering issues, missing security headers, improper rate limiting, and URL normalization bypasses. The `@fastify/express` compatibility layer introduces additional attack surface.

---

## 1. CVE-2026-33808 — Fastify-Express Middleware Authentication Bypass

**CVSS:** 9.1 (Critical, CVSS 4.0)  
**CWE:** CWE-436 (Interpretation Conflict)  
**Affected:** `@fastify/express` <= 4.0.4 (fixed in 4.0.5)  
**Description:** When Fastify router normalization options are enabled (`ignoreDuplicateSlashes` or `useSemicolonDelimiter`), the Fastify router normalizes and matches the incoming path, but `@fastify/express` passes the original **un-normalized** URL to Express middleware. Path-scoped auth/authorization/rate-limiting middleware then fails to match and is silently skipped — letting an unauthenticated attacker reach protected routes via duplicate slashes or semicolon delimiters. Note: exploitation requires those non-default normalization options to be enabled.

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — @fastify/express < 4.0.5
import fastifyExpress from "@fastify/express";
import express from "express";

const app = fastify();

await app.register(fastifyExpress);

const authMiddleware = express.Router();
authMiddleware.use((req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).send("Unauthorized");
  }
  next();
});

// 💀 Attacker can bypass with URL normalization tricks
// e.g., GET /admin//../protected/resource
app.use("/admin", authMiddleware, (req, res) => {
  res.send("Admin panel");
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Upgrade @fastify/express to >= 4.0.5
// And add URL normalization as defense in depth
import fastifyExpress from "@fastify/express";

const app = fastify();

await app.register(fastifyExpress);

// ✅ Defense in depth — normalize URLs before middleware
app.addHook("onRequest", async (request) => {
  // Normalize URL path
  request.url = new URL(request.url, "http://localhost").pathname;
});
```

**Source:**
- https://nvd.nist.gov/vuln/detail/CVE-2026-33808
- https://github.com/fastify/fastify-express/security/advisories/GHSA-6hw5-45gm-fj88

---

## 2. Security Headers — Helmet

### Missing Helmet

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No security headers
import express from "express";

const app = express();

app.get("/", (req, res) => {
  res.send("Hello World");
  // 💀 No security headers!
  // Missing: X-Content-Type-Options, X-Frame-Options, CSP, etc.
});

app.listen(3000);
```

**Secure Code:**
```javascript
// ✅ SECURE — Helmet adds security headers
import express from "express";
import helmet from "helmet";

const app = express();

app.use(helmet());  // ✅ Must be first middleware

// ⚠️ Customize in production:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.example.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));
```

### Common AI Misconfiguration

```javascript
// 💀 VULNERABLE — AI code often has helmet too late or incomplete
import express from "express";

const app = express();

// CORS before helmet
app.use(cors());  // 💀 Should be after helmet
app.use(helmet());  // Too late for some headers

// Or missing helmet entirely when using body-parser, cookie-parser, etc.
```

---

## 3. Middleware Ordering — Authentication Before Body Parser

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Authentication after body parsing (DoS risk)
import express from "express";

const app = express();

// Body parser first — parses large payloads before auth check
app.use(express.json({ limit: "10mb" }));          // 💀 Parses even malicious payloads
app.use(express.urlencoded({ extended: true }));

app.use("/api/admin", authenticate);
app.use("/api/admin", adminRouter);

// 💀 Unauthenticated users can cause DoS by sending large JSON payloads
```

**Secure Code:**
```javascript
// ✅ SECURE — Authentication before body parsing for protected routes
import express from "express";

const app = express();

// Public routes first — with body parsing
app.use("/api/public", express.json({ limit: "1mb" }));
app.use("/api/public", publicRouter);

// Protected routes — authenticate before body parsing
app.use("/api/admin", authenticate);

// ⚠️ Parse body only after authentication
// Either inline in the router or conditionally
app.use("/api/admin", express.json({ limit: "100kb" }));  // ✅ Smaller limit
app.use("/api/admin", adminRouter);

// OR skip body parsing for unauthenticated requests
app.use((req, res, next) => {
  if (req.path.startsWith("/api/admin") && !req.user) {
    return res.status(401).send("Unauthorized");
  }
  next();
});
```

---

## 4. Rate Limiting

### No Rate Limiting

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No rate limiting at all
import express from "express";

const app = express();

app.post("/api/login", async (req, res) => {
  // 💀 Unauthenticated brute force — no rate limiting
  const user = await authenticate(req.body.username, req.body.password);
  res.json({ token: generateToken(user) });
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Rate limiting with express-rate-limit
import express from "express";
import rateLimit from "express-rate-limit";

const app = express();

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
});
app.use(globalLimiter);

// Stricter limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                      // 5 attempts per 15 minutes
  skipSuccessfulRequests: false,
  message: { error: "Too many login attempts" },
});
app.use("/api/login", authLimiter);

// Very strict limiter for password reset
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,   // 1 hour
  max: 3,                      // 3 per hour
  message: { error: "Too many password reset requests" },
});
app.use("/api/reset-password", passwordResetLimiter);
```

### Rate Limiting Bypass via IP Spoofing

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Rate limiting uses spoofable IP
import rateLimit from "express-rate-limit";
import express from "express";

const app = express();

// Using default IP extraction — vulnerable to X-Forwarded-For spoofing
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  // 💀 express-rate-limit may use req.ip which can be spoofed
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Trust proxy correctly
import rateLimit from "express-rate-limit";
import express from "express";

const app = express();

// ✅ Must set trust proxy for accurate IP behind reverse proxies
app.set("trust proxy", 1);   // Trust first proxy

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => {
    // ✅ Use a combination of factors for rate limiting
    return `${req.ip}:${req.headers["user-agent"] || "unknown"}`;
  },
});
```

---

## 5. Session Security

### Insecure Session Configuration

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Insecure Express session
import session from "express-session";
import express from "express";

const app = express();

app.use(session({
  secret: "keyboard cat",              // 💀 Weak, hardcoded secret
  resave: false,
  saveUninitialized: true,              // 💀 Creates sessions for unauthenticated users
  cookie: {
    secure: false,                      // 💀 Over HTTP
    httpOnly: false,                    // 💀 Accessible via JavaScript
    maxAge: null,                       // 💀 Session cookie — never expires
    sameSite: false,                    // 💀 No SameSite protection
  },
}));
```

**Secure Code:**
```javascript
// ✅ SECURE — Proper session configuration
import session from "express-session";
import express from "express";
import crypto from "crypto";

const app = express();

// Generate a strong secret
const SESSION_SECRET = process.env.SESSION_SECRET 
  || crypto.randomBytes(64).toString("hex");

app.use(session({
  secret: SESSION_SECRET,               // ✅ Strong secret from environment
  resave: false,
  saveUninitialized: false,             // ✅ Only create session when needed (after auth)
  rolling: true,                        // ✅ Reset expiry on each request
  name: "__Host-sess",                  // ✅ Prefix indicates secure cookie
  cookie: {
    secure: true,                       // ✅ HTTPS only
    httpOnly: true,                     // ✅ Not accessible via JavaScript
    maxAge: 1000 * 60 * 60 * 8,        // ✅ 8 hours max
    sameSite: "lax",                    // ✅ SameSite protection
    path: "/",
    domain: process.env.COOKIE_DOMAIN,  // ✅ Explicit domain
  },
}));

// For production — use session store (not default MemoryStore)
import RedisStore from "connect-redis";
import { createClient } from "redis";

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 8,
    sameSite: "lax",
  },
}));
```

---

## 6. CSRF Protection

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No CSRF protection
import express from "express";

const app = express();

app.post("/api/transfer", (req, res) => {
  // 💀 Accepts cross-origin POST requests without CSRF token
  transferMoney(req.user.id, req.body.amount, req.body.toAccount);
  res.send("OK");
});
```

**Secure Code:**
```javascript
// ✅ SECURE — CSRF protection with csurf (or double-submit cookie)
import express from "express";
import csrf from "csurf";

const app = express();

// CSRF protection middleware
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    key: "_csrf",
  },
});

// Apply to state-changing routes
app.use("/api", csrfProtection);

app.get("/api/csrf-token", (req, res) => {
  // Send CSRF token to client
  res.json({ csrfToken: req.csrfToken() });
});

app.post("/api/transfer", csrfProtection, (req, res) => {
  transferMoney(req.user.id, req.body.amount, req.body.toAccount);
  res.send("OK");
});

// ✅ OR for SPA using SameSite cookies as CSRF protection:
app.use(session({ /* secure session config */ }));

// For APIs — use token-based auth (JWT) + CORS
```

---

## 7. CORS Misconfiguration

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Wildcard CORS
import cors from "cors";

app.use(cors());  // 💀 Allow all origins

// OR
app.use(cors({
  origin: "*",
  credentials: true,   // 💀 ILLEGAL with *
}));
```

**Secure Code:**
```javascript
// ✅ SECURE — Restricted CORS
import cors from "cors";

const whitelist = ["https://app.example.com", "https://admin.example.com"];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, mobile apps)
    if (!origin) return callback(null, true);
    
    if (whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Authorization", "Content-Type"],
  exposedHeaders: ["X-Request-Id"],
  credentials: false,        // ✅ Avoid credentials if possible
  maxAge: 86400,             // 24 hours preflight cache
}));
```

---

## 8. Input Validation

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No input validation
import express from "express";

const app = express();

app.post("/api/user", (req, res) => {
  const { username, email, role } = req.body;
  // 💀 Direct object insertion — mass assignment
  User.create({ username, email, role });  // role can be set to "admin"
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Input validation with express-validator
import { body, validationResult } from "express-validator";

app.post("/api/user",
  body("username").isAlphanumeric().isLength({ min: 3, max: 30 }).trim().escape(),
  body("email").isEmail().normalizeEmail(),
  body("role").not().exists(),            // ✅ Role must not be set by user
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // ✅ Only allow safe fields
    const { username, email } = req.body;
    User.create({ username, email, role: "user" });  // ✅ Force safe role
    res.status(201).json({ success: true });
  }
);

// ✅ OR use Zod for validation
import { z } from "zod";

const userSchema = z.object({
  username: z.string().min(3).max(30),
  email: z.string().email(),
  role: z.undefined(),  // ❌ Must not be provided
});

app.post("/api/user", (req, res) => {
  const parsed = userSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.flatten() });
  }
  
  User.create({ ...parsed.data, role: "user" });
  res.status(201).json({ success: true });
});
```

---

## 9. Error Handling — Information Leakage

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Detailed error messages in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,          // 💀 Exposes internal details
    stack: err.stack,            // 💀 Full stack trace
    code: err.code,
  });
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Generic error messages in production
app.use((err, req, res, next) => {
  // ✅ Log full details server-side
  console.error("Server error:", {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  // ✅ Only send safe error response
  res.status(err.statusCode || 500).json({
    error: process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message,
    requestId: req.id,  // ✅ Traceable without details
  });
});
```

---

## 10. Fastify-Specific Security

### Fastify Schema Validation

```javascript
// ✅ SECURE — Fastify schema validation (built-in)
import Fastify from "fastify";

const app = Fastify({ logger: true });

app.post("/api/user", {
  schema: {
    body: {
      type: "object",
      required: ["username", "email"],
      properties: {
        username: { type: "string", minLength: 3, maxLength: 30 },
        email: { type: "string", format: "email" },
        role: { type: "string", enum: ["user"] },  // ✅ Only valid role
      },
      additionalProperties: false,  // ✅ Reject unknown fields
    },
    response: {
      201: {
        type: "object",
        properties: {
          id: { type: "string" },
          username: { type: "string" },
        },
      },
    },
  },
}, async (request, reply) => {
  // ✅ Already validated by schema
  const user = await createUser(request.body);
  reply.code(201).send({ id: user.id, username: user.username });
});
```

---

## 11. CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2026-33808 | 9.1 | @fastify/express <= 4.0.4 | Auth bypass via URL normalization drift (CWE-436) | 4.0.5 |
| CVE-2024-45296 | 7.5 | path-to-regexp < 0.1.10 (bundled in express <= 4.21.0) | ReDoS via backtracking regex (not path traversal) | path-to-regexp 0.1.10; express 4.21.1 |
| CVE-2024-29041 | 5.3 | express < 4.19.2 | Open Redirect via malformed URL (`res.location`/`res.redirect`) | 4.19.2 |
| CVE-2024-43799 | 5.0 | send < 0.19.0 (bundled in express < 4.20.0) | Template injection → XSS via `SendStream.redirect()` | send 0.19.0; express 4.20.0 |

---

## 12. Version Recommendations

| Library | Version | Status |
|---------|---------|--------|
| express | 4.21.x | ✅ Latest |
| fastify | 5.2.x | ✅ Latest |
| @fastify/express | 4.0.5+ | ✅ Critical fix |
| helmet | 8.x | ✅ Latest |
| express-rate-limit | 7.x | ✅ Latest |
| cors | 2.8.x | ✅ Stable (use restrictively) |

---

## 13. Common AI-Produced Misconfigurations

1. **Helmet not installed or placed too late** — Missing security headers
2. **No rate limiting** — Brute force vulnerability
3. **Weak/static session secret** — `express-session` with "keyboard cat"
4. **`saveUninitialized: true`** — Wastes resources on anonymous sessions
5. **`secure: false` for session cookies** — Auth cookies over HTTP
6. **`cors()` with no options** — Accepts all origins
7. **No CSRF protection for APIs** — Missing anti-forgery tokens
8. **Error details in production** — Stack traces leaked to clients
9. **`express.json({ limit: "10mb" })` before auth** — DoS vector
10. **No input validation** — Missing schema/param validation (mass assignment)
11. **@fastify/express URL normalization bypass** — CVE-2026-33808 pattern

---

## Verification / Source URLs

- CVE-2026-33808 (@fastify/express): https://nvd.nist.gov/vuln/detail/CVE-2026-33808
- Fastify Express Advisory: https://github.com/fastify/fastify-express/security/advisories/GHSA-6hw5-45gm-fj88
- Express Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html
- Helmet.js: https://helmetjs.github.io/
- express-rate-limit: https://express-rate-limit.mintlify.app/
- OWASP Node.js Security: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- Fastify Security: https://www.fastify.io/docs/latest/Guides/Serverless/
