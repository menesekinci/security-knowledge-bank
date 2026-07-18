---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "6. Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 8/10
---

## 6. Prevention Checklist

- [ ] **Use `{{ }}` or `v-text` instead of `v-html`** — If `v-html` is unavoidable, sanitize with DOMPurify
- [ ] **Use runtime-only Vue build** — Avoid the full build with template compiler in production to prevent CVE-2024-6783
- [ ] **Keep Nuxt updated** — Pin to Nuxt 3.21.7+ or 4.4.7+ to patch the 2026 CVE batch
- [ ] **Lock `@nuxt/devtools`** — Use version 1.3.9+ (CVE-2024-23657)
- [ ] **Never expose secrets via `runtimeConfig.public`** — Server-only secrets go in `runtimeConfig` (no `.public` suffix)
- [ ] **Use Nitro server routes for sensitive operations** — Server-side auth checks in `server/api/` not client-side `useFetch`
- [ ] **Validate all URLs in `<NuxtLink>` and `navigateTo`** — Reject `javascript:`, `vbscript:`, `data:` protocols
- [ ] **Configure CSP headers** — Use `nuxt-security` module or manual `app.head.meta` entries
- [ ] **Disable component islands if not needed** — Set `experimental: { componentIslands: false }` in Nuxt 3
- [ ] **Avoid `nuxt dev --host` in development** — Prevents CVE-2025-24360 and CVE-2026-45670 source exposure
- [ ] **Validate `routeRules` case sensitivity** — Test that `/Admin` and `/admin` both trigger middleware
- [ ] **Set `sameSite: 'lax'` on auth cookies** — Prevent CSRF
- [ ] **Use `$fetch` with explicit credentials** — Ensure API calls include auth headers server-side
- [ ] **Audit AI-generated Nuxt middleware** — Verify it doesn't return empty `{}` or skip auth checks
- [ ] **Scan with `nuxt-security` module** — Run `npx nuxt-security check` in CI

---