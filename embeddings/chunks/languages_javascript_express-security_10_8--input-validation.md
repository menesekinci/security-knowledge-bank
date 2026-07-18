---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "8. Input Validation"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 10/16
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