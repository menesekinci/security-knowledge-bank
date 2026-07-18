---
source: "languages/javascript/express-security.md"
title: "Express / Fastify Security Deep Dive"
heading: "10. Fastify-Specific Security"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2026-33808, fastify-express, headers, javascript, language-vuln, limiting, middleware, ordering, overview, rate]
chunk: 12/16
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