---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 8
total_chunks: 16
heading: "6. CSRF Protection"
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