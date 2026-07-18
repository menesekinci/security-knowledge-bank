---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "9. Error Handling — Information Leakage"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 11/16
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