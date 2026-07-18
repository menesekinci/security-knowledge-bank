---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "Prevention Checklist (Zod / Runtime Validation Integration)"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 5/8
---

## Prevention Checklist (Zod / Runtime Validation Integration)

- [ ] **Enable `strict: true`** in `tsconfig.json` — enables `noImplicitAny`, `strictNullChecks`, `strictFunctionTypes`
- [ ] **Ban `any`** — Use `eslint` rule `@typescript-eslint/no-explicit-any: error`. Use `unknown` instead and narrow with type guards
- [ ] **Ban `// @ts-ignore`** — Use `@typescript-eslint/ban-ts-comment: error`. Use `// @ts-expect-error` with a reason only when absolutely necessary
- [ ] **Use Zod (or io-ts, valibot) for ALL external data** — Every API response, JSON.parse, form submission, config file must pass a runtime schema validator
- [ ] **Ban `as` casts on external data** — Never use `JSON.parse(x) as T`. Always parse through a schema validator
- [ ] **Never use `as` for auth/user data** — JWT payloads, session data, and user objects must be validated with runtime schemas
- [ ] **Use branded types** for IDs and tokens to prevent type confusion between strings that represent different domains
- [ ] **Add pre-commit hooks** — `lint-staged` + `eslint` catches type escapes before they reach CI
- [ ] **Audit `// @ts-expect-error`** — Review every suppression in code review; most can be eliminated with proper generics
- [ ] **Runtime type guards for critical paths** — Use TypeScript's `x is T` return type for reusable validation functions

---