# TypeScript Hardening Checklist

> Vibe-coding security checklist for TypeScript projects before deploy / merge.  
> Related: [type-safety-bypass.md](type-safety-bypass.md), [decorator-abuse.md](decorator-abuse.md), [reflect-metadata.md](reflect-metadata.md)

---

## 1. Type system as a non-boundary

- [ ] `strict: true` in `tsconfig.json` (`strictNullChecks`, `noImplicitAny`, `strictFunctionTypes`)
- [ ] No project-wide `// @ts-nocheck`
- [ ] CI fails on `tsc --noEmit` errors (do not "fix later")
- [ ] Ban or gate `as any` / `as unknown as T` via ESLint (`@typescript-eslint/no-explicit-any`, `no-unsafe-*`)
- [ ] `@ts-ignore` / `@ts-expect-error` require justification comment and ticket link

## 2. Runtime validation (types are erased)

- [ ] All external input (HTTP body, query, headers, webhooks, env) validated at runtime (Zod / Yup / io-ts / typia / class-validator)
- [ ] Do not trust `req.body as User` — parse with schema
- [ ] GraphQL / tRPC / OpenAPI handlers use generated or schema-bound types end-to-end
- [ ] File uploads: MIME + size + content sniffing, not only extension

## 3. XSS / HTML / templates

- [ ] No `dangerouslySetInnerHTML` without sanitizer (DOMPurify) + CSP
- [ ] No `innerHTML` / `document.write` with untrusted strings
- [ ] React/Vue auto-escape assumed only for text children — not for URLs (`javascript:`), CSS, or attribute injection
- [ ] Markdown/HTML renderers use safe mode / allowlist

## 4. Injection & data access

- [ ] SQL/NoSQL via parameterized queries / ORM bind parameters only
- [ ] No string-interpolated SQL in `query`/`execute`
- [ ] Shell: never `exec(userString)` — use `execFile` + argv array
- [ ] Path operations: resolve + root jail; reject `..`

## 5. AuthN / AuthZ

- [ ] JWT: explicit `algorithms` allowlist; reject `none`; validate `iss`/`aud`/`exp`
- [ ] Authorization checked server-side per resource (IDOR-safe); types do not enforce ACL
- [ ] Cookies: `HttpOnly`, `Secure`, `SameSite`; CSRF strategy for cookie sessions
- [ ] SSR / RSC: secrets never serialized into client bundles

## 6. Supply chain & config

- [ ] Lockfile committed; `npm ci` / `pnpm i --frozen-lockfile` in CI
- [ ] Dependabot/Renovate + `npm audit` / OSV / Snyk gate
- [ ] No install of AI-hallucinated package names without registry verify
- [ ] Secrets only in env / secret manager — not in source or client env (`NEXT_PUBLIC_*` careful)

## 7. Network & browser

- [ ] CORS: explicit origins; never `*` + `credentials: true`
- [ ] `postMessage`: explicit `targetOrigin`; validate `event.origin`
- [ ] CSP with nonces/hashes; avoid `unsafe-inline` / `unsafe-eval` where possible
- [ ] Service workers: scoped, HTTPS, update strategy reviewed

## 8. Decorators / reflect-metadata

- [ ] Decorator order and metadata not used as sole auth mechanism
- [ ] `emitDecoratorMetadata` consumers validate runtime types (design:type is limited)
- [ ] Avoid dynamic `Reflect.defineMetadata` from user input

## 9. Build / tooling

- [ ] Source maps not exposed on production web roots
- [ ] Production build strips devtools-only flags
- [ ] ESLint security plugins (`eslint-plugin-security`, `eslint-plugin-no-secrets`) optional but recommended
- [ ] Semgrep: `semgrep --config ../../semgrep-rules/vibe-typescript.yml` + `vibe-javascript.yml` + `vibe-dangerous.yml`

## 10. Vibe-coding red flags (reject AI output if…)

- [ ] Suggests `as any` to "just make it compile"
- [ ] Uses `@ts-ignore` on auth or crypto lines
- [ ] Builds SQL/HTML with template literals from user data
- [ ] Disables TLS (`NODE_TLS_REJECT_UNAUTHORIZED=0`)
- [ ] Copies secrets into frontend code
- [ ] Invents npm package names (verify on registry)

---

## Minimal `tsconfig` baseline

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "skipLibCheck": true
  }
}
```

## Minimal ESLint gate (idea)

```js
// @typescript-eslint/no-explicit-any: error
// @typescript-eslint/no-unsafe-assignment: warn/error
// no-eval: error
```

---

*Last updated: July 2026 — Vibe Coding Security Knowledge Bank*
