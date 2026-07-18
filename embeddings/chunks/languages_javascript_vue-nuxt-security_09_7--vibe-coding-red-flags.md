---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "7. Vibe-Coding Red Flags"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 7. Vibe-Coding Red Flags

When reviewing AI-generated Vue/Nuxt code, flag these instantly:

| Red Flag | Why |
|----------|-----|
| `v-html="userInput"` or `v-html="query"` | Classic XSS — use `{{ }}` or `v-text` |
| `process.env.API_KEY` in a `.vue` file | Secret exposed to client bundle |
| `runtimeConfig.public.{secret}` | Server secret leaked to client |
| Middleware that reads `true` or returns `{}` | Middleware does nothing — no auth enforced |
| `useFetch('/api/...')` without auth headers | Server data accessible to anyone |
| `nuxt.config.ts` without CSP | No XSS mitigation at HTTP level |
| `navigateTo(url, { external: true })` with user input in `url` | XSS via HTML meta-refresh injection (CVE-2026-45669) |
| `<NuxtLink :to="user.url">` without validation | XSS via `javascript:` URL (CVE-2026-53722) |
| `experimental: { componentIslands: true }` (Nuxt 3) without understanding the island bypass | Middleware bypass via `/__nuxt_island/` (CVE-2026-47200) |
| `ssr: false` on pages with auth middleware | Disabling SSR removes server-side protection |
| `@nuxt/devtools` in production dependencies | Devtools should be devDependencies only |
| Using the full Vue build (`vue` instead of `vue.runtime`) | Template compiler XSS surface (CVE-2024-6783) |
| `import.meta.env` without the `VITE_` / `NUXT_PUBLIC_` convention check | Wrong prefix = secret in bundle or missing from client |

---