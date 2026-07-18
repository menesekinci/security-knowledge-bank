---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 16
heading: "2. Security Headers — Helmet"
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