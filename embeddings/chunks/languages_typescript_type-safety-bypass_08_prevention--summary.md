---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "Prevention (Summary)"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 8/8
---

## Prevention (Summary)

- Use `unknown` instead of `any`
- Do not use `// @ts-ignore`
- Use type guards / validation instead of `as` casts
- Configure TS with `strict: true`
- Use runtime validation libraries such as Zod / io-ts
- Validate all external data (API response, JSON.parse, config) with a schema

---

**Severity: 🟡 Medium–High** — Runtime errors, loss of type safety, auth bypass, potential RCE.