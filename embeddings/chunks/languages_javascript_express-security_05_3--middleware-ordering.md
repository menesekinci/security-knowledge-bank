---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "3. Middleware Ordering — Authentication Before Body Parser"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 5/16
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