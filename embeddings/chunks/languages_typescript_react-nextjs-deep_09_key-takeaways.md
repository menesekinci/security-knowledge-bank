---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "Key Takeaways"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 9/10
---

## Key Takeaways

1. **Framework isolation is not security isolation** — the RSC boundary, middleware, and `'use client'` directive are optimization features, not security guarantees
2. **Every server endpoint needs independent auth** — Server Actions, Route Handlers, and pages must each verify authentication and authorization
3. **AI amplifies framework-level CVEs** — generated code uses default patterns that are most impacted by framework bugs (middleware-only auth, RSC deserialization)
4. **Defense in depth is non-negotiable** — middleware + layout auth + handler auth + input validation + output encoding
5. **Keep React and Next.js patched** — multiple critical CVEs in 2025-2026 demonstrate active exploitation of framework bugs
6. **Runtime validation beats type safety** — TypeScript types erase at runtime; Zod (or equivalent) is mandatory for all I/O boundaries

---