---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "6. Prevention Checklist (15 Items)"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 7/10
---

## 6. Prevention Checklist (15 Items)

- [ ] **Upgrade React to ≥ 19.0.4** (or 19.1.5+, 19.2.4+) to patch CVE-2025-55182 and CVE-2026-23864
- [ ] **Upgrade Next.js to ≥ 15.2.3** (or 14.2.25+) to patch CVE-2025-29927; ≥ 15.4.7 for CVE-2025-57822
- [ ] **Authenticate in every Server Action** — never rely solely on middleware for auth; verify `auth()` at the top of every `'use server'` function
- [ ] **Authorize by ownership** — in every mutation, verify `post.authorId === session.user.id` (or admin override)
- [ ] **Validate all input with Zod** — define exact schemas; never pass `Object.fromEntries(formData)` directly to a database
- [ ] **Use route group layouts for protected routes** — wrap `/admin` in `(admin)/layout.tsx` with server-side auth
- [ ] **Strip dangerous headers in middleware** — explicitly remove `x-middleware-subrequest` at the edge
- [ ] **Never upload files to `public/`** — store uploads outside the web root; serve through authenticated API endpoints
- [ ] **Validate file uploads strictly** — check MIME type, magic bytes, file size, and use UUID-based filenames
- [ ] **Avoid `'use client'` on data-fetching components** — keep data fetching in Server Components; only add `'use client'` for interactivity
- [ ] **Never expose secrets in client components** — `NEXT_PUBLIC_*` is visible to every visitor; use `process.env.SERVER_SECRET` only in Server Components/Actions
- [ ] **Block prototype pollution vectors** — guard `__proto__`, `constructor`, `prototype` in key-setting utilities; use `Object.create(null)` for FormData accumulators
- [ ] **Prevent open redirects** — validate redirect URLs against an allowlist; never accept user-controlled `redirect` params
- [ ] **Add CSP headers** — use middleware or `next.config.js` headers to add Content-Security-Policy: `script-src 'self'; object-src 'none'`
- [ ] **Run security scanning** — use `npm audit`, Snyk, or Semgrep rules (`vibe-javascript.yml`, `vibe-typescript.yml`) in CI

---