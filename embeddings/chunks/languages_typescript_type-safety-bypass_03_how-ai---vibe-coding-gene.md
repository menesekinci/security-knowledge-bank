---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

LLMs are optimized to make code compile. When TypeScript complains, the easiest fix the model can emit is:

```typescript
// @ts-ignore  ← AI's favorite shortcut
// as any      ← AI's second favorite
// as T        ← lies to compiler, no runtime check
```

Common AI-generated patterns:

| Pattern | What AI Does | Why It's Dangerous |
|---------|-------------|-------------------|
| `as any` on API response | Silences type error, assumes shape | No runtime validation of external data |
| `// @ts-ignore` above complex generic | Makes build pass | Hides real type mismatches |
| `as User` on `JSON.parse()` result | Tells compiler "trust me" | User is never validated at runtime |
| `any` in function params | Quick fix for "no overload matches" | Callers can pass anything |
| Non-null assertion `user!.name` | Suppresses `undefined` | Crashes if value is actually null/undefined |

---