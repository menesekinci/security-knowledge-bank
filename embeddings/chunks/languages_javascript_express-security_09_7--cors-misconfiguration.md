---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "7. CORS Misconfiguration"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 9/16
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