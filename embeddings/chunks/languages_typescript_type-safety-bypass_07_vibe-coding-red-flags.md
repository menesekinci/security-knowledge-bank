---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 7/8
---

## Vibe-Coding Red Flags

- `as any` in API response handlers — especially on `fetch()` or `axios` responses
- `// @ts-ignore` or `// @ts-expect-error` used to silence array/object access complaints
- `JSON.parse(x) as T` pattern — 100% of AI code generators emit this
- Functions typed as accepting `any` that are called with untrusted user input
- No Zod/io-ts/class-validator schemas in projects that handle external data
- Non-null assertions (`!`) used as a substitute for actual null checking
- Type-only DTOs (`interface` or `type`) used for request bodies without runtime validation
- `as` casts in the same file as `document.cookie`, `localStorage`, or `fetch()` — indicates data is being trusted without validation
- Importing a Zod/valibot schema but never calling `.parse()` — common in AI boilerplate

---