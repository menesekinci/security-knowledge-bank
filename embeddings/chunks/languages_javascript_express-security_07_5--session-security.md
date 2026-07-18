---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "5. Session Security"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 7/16
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