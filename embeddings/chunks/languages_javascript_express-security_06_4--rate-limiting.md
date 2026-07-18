---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "4. Rate Limiting"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 6/16
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