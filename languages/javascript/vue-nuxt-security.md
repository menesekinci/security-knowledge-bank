# Vue.js & Nuxt Security Deep Dive

> **Category:** JavaScript / Vue.js Security Knowledge Bank  
> **Focus:** v-html XSS, CSP headers, middleware bypass, client-side secret exposure, SSR data leakage, island rendering attacks  
> **Severity:** High  
> **CWE:** CWE-79 (XSS), CWE-284 (Access Control), CWE-200 (Info Exposure), CWE-346 (CORS), CWE-352 (CSRF)  
> **AI Generation Risk:** High  
> **Last Updated:** July 2026

---

## Overview

Vue.js and Nuxt are among the most popular frameworks for AI-generated frontends. Vue's reactivity system and template syntax provide solid default XSS protections — but there are well-known escape hatches (`v-html`, `innerHTML` in lifecycle hooks) that AI models frequently use without sanitization. Nuxt adds server-side rendering, middleware, and island components, each introducing its own attack surface.

The 2025–2026 disclosure wave of Nuxt CVEs (over a dozen high-severity issues) makes this a critical area for security review. Many of these vulnerabilities — middleware bypass, island cache poisoning, open redirect — parallel the Next.js vulnerability landscape and affect the same AI-generated "dashboard" and "admin panel" patterns.

---

## 1. Vulnerability Explanation — Vue/Nuxt Specific Risks

### 1.1 `v-html` with User Input (Classic XSS)

Vue's `v-html` directive renders raw HTML into an element. Unlike React's `dangerouslySetInnerHTML` (which at least has an obvious name), `v-html` looks innocuous to AI code generators. When AI binds user input directly to `v-html`, the result is DOM-based XSS.

```vue
<!-- 💀 VULNERABLE — User content rendered as raw HTML -->
<div v-html="user.comment"></div>
<!-- user.comment = <img src=x onerror=alert('XSS')> -->
```

Vue 3's build (full vs. runtime) affects XSS surface: the "full build" includes a runtime template compiler, which means user-provided template strings can execute arbitrary code if compiled at runtime.

### 1.2 Missing CSP Headers in Nuxt Config

Nuxt applications that lack Content-Security-Policy headers cannot mitigate script injection at the browser level. AI-generated Nuxt configs frequently omit CSP entirely or use overly permissive directives like `script-src 'unsafe-inline'`.

### 1.3 Nuxt Middleware Bypass

Nuxt's route middleware (`definePageMeta({ middleware: [...] })`) is bypassable through several vectors:

- **Case-sensitivity mismatch** between `vue-router` and the `routeRules` matcher (CVE-2026-53721)
- **Island endpoints** (`/__nuxt_island/page_*`) that render pages without invoking Vue Router (CVE-2026-47200)
- **Route rules with incorrect path normalization** — middleware assigned via `routeRules` may not execute if the route is accessed with different casing

AI-generated "admin" pages often rely solely on middleware for access control with no server-side Nitro validation, making every bypass critical.

### 1.4 Insecure API Key Exposure in Client-Side Env Vars

Nuxt exposes environment variables to the client bundle through `publicRuntimeConfig` and `runtimeConfig.public`. AI generators commonly prefix all `.env` variables with `NUXT_PUBLIC_` or use `process.env.API_KEY` directly in Vue components — which bundles the secret into client-side JavaScript.

### 1.5 Server-Side Data Exposure via `useFetch` Without Auth

Nuxt's `useFetch` in server components and Nitro routes can leak data when called without authentication checks. AI-generated code often fetches data directly from the server without verifying the user's session:

```vue
<script setup>
// 💀 VULNERABLE — No auth check
const { data } = await useFetch('/api/admin/users')
</script>
```

---

## 2. How AI / Vibe Coding Generates This

### "Create a Vue Dashboard"
AI produces:
```vue
<template>
  <div v-html="dashboardData"></div>
</template>
<script>
export default {
  data() { return { dashboardData: '<h1>Loading...</h1>' } },
  mounted() {
    fetch('/api/dashboard', { headers: { 'X-API-Key': process.env.VUE_APP_API_KEY }})
      .then(r => r.json()).then(d => { this.dashboardData = d.html })
  }
}
</script>
```
Problems: XSS via `v-html`, API key in client bundle, no auth header.

### "Add Search to the Page"
```vue
<div v-html="`Search results for: ${query}`"></div>
```
The AI uses `v-html` instead of `{{ }}` because it assumes HTML rendering is needed — but the search term is unsanitized.

### "Deploy with Nuxt"
AI generates a minimal `nuxt.config.ts` with no CSP:
```ts
export default defineNuxtConfig({
  // ❌ No CSP, no security headers
  app: { head: { title: 'My App' } }
})
```

### "Add Admin Panel"
```ts
// 💀 Middleware that does nothing
export default defineNuxtMiddleware(() => {})
```
Or worse — returning empty `{}` from middleware, allowing all routes through.

---

## 3. Vulnerable Code Examples

### 3.1 v-html XSS

```vue
<!-- 💀 VULNERABLE — Direct user input in v-html -->
<template>
  <div class="comment">
    <div v-html="comment.body"></div>
    <span>{{ comment.author }}</span>
  </div>
</template>

<script setup>
const props = defineProps(['comment'])
</script>
```

### 3.2 Client-Side Secret Exposure

```vue
<!-- 💀 VULNERABLE — Secrets in client bundle -->
<script setup>
// process.env.API_KEY is bundled into client-side JS
const stripeKey = process.env.STRIPE_SECRET_KEY

const chargeUser = async () => {
  await fetch('https://api.stripe.com/v1/charges', {
    headers: { 'Authorization': `Bearer ${stripeKey}` }
  })
}
</script>
```

### 3.3 Nuxt Middleware Returning Empty Object

```ts
// 💀 VULNERABLE — Middleware that doesn't enforce auth
// middleware/auth.ts
export default defineNuxtRouteMiddleware(() => {
  // ❌ AI forgot to add auth check — returns undefined, allows all
})
```

### 3.4 useFetch Without Auth

```vue
<script setup>
// 💀 VULNERABLE — No auth mechanism on server data access
const { data: users } = await useFetch('/api/admin/users')
// Anyone can call /api/admin/users — no JWT, no session check
</script>
```

### 3.5 Nuxt Config Without CSP

```ts
// nuxt.config.ts — 💀 VULNERABLE
export default defineNuxtConfig({
  compatibilityDate: '2024-11-01',
  // ❌ No app.head.script or CSP configuration
  // ❌ No security module configured
})
```

### 3.6 Insecure CORS in Development

```ts
// nuxt.config.ts — 💀 VULNERABLE (affects dev)
export default defineNuxtConfig({
  nitro: {
    devServer: {
      watch: [],
    },
  },
  // Default CORS allows any origin in dev mode — CVE-2025-24360
})
```

---

## 4. Secure Code Fix

### 4.1 v-html → Safe Alternatives

```vue
<!-- ✅ SECURE — Use text interpolation or v-text -->
<template>
  <div class="comment">
    <div>{{ comment.body }}</div>
    <span>{{ comment.author }}</span>
  </div>
</template>
```

If raw HTML is genuinely required:

```vue
<template>
  <div v-html="sanitizedBody"></div>
</template>

<script setup>
import DOMPurify from 'dompurify'

const props = defineProps(['comment'])
const sanitizedBody = computed(() =>
  DOMPurify.sanitize(props.comment.body, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'class'],
  })
)
</script>
```

### 4.2 Runtime Config — Never Expose Secrets

```ts
// nuxt.config.ts — ✅ SECURE
export default defineNuxtConfig({
  runtimeConfig: {
    // Server-side only — never exposed to client
    stripeSecretKey: process.env.STRIPE_SECRET_KEY,

    // Client-accessible — only non-sensitive values
    public: {
      siteName: 'My App',
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    },
  },
})
```

Usage:

```vue
<script setup>
// ✅ SECURE — Only public config is accessible on client
const config = useRuntimeConfig()
const publishableKey = config.public.stripePublishableKey

// ❌ This is undefined on client — secret stays server-side
console.log(config.stripeSecretKey) // undefined in browser
</script>
```

### 4.3 Proper Middleware with Auth Checks

```ts
// middleware/auth.ts — ✅ SECURE
export default defineNuxtRouteMiddleware((to, from) => {
  const token = useCookie('auth_token')

  if (!token.value) {
    return navigateTo('/login')
  }

  // Verify token validity server-side for protected routes
  if (to.path.startsWith('/admin') && !hasAdminRole(token.value)) {
    return navigateTo('/403')
  }
})

// ✅ Always use routeRules for additional protection:
// nuxt.config.ts
export default defineNuxtConfig({
  routeRules: {
    '/admin/**': { ssr: true },  // server-rendered with full middleware
    '/api/admin/**': {
      // Use Nitro server routes for sensitive operations
      redirect: '/api/nitro/admin',
    },
  },
})
```

### 4.4 Nitro Server Routes for Sensitive Operations

```ts
// server/api/admin/users.get.ts — ✅ SECURE
export default defineEventHandler(async (event) => {
  // ✅ Auth check at the server level
  const session = await getServerSession(event)
  if (!session || !session.isAdmin) {
    throw createError({ statusCode: 403, statusMessage: 'Forbidden' })
  }

  const users = await User.find({}).select('-passwordHash')
  return { users }
})
```

### 4.5 Nuxt Config with CSP and Security Headers

```ts
// nuxt.config.ts — ✅ SECURE
export default defineNuxtConfig({
  app: {
    head: {
      title: 'My App',
      meta: [
        { 'http-equiv': 'Content-Security-Policy',
          content: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https:; connect-src 'self' https://api.example.com" },
      ],
    },
  },
  nitro: {
    experimental: {
      openAPI: false,  // Disable if not needed
    },
  },
})
```

Alternatively, use [nuxt-security](https://github.com/Baroshem/nuxt-security) module:

```ts
export default defineNuxtConfig({
  modules: ['nuxt-security'],
  security: {
    headers: {
      contentSecurityPolicy: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'https:'],
      },
      xFrameOptions: 'DENY',
      xContentTypeOptions: 'nosniff',
    },
    rateLimiter: {
      // Rate limit API endpoints
      routes: {
        '/api/**': { maxRequests: 100, interval: 60000 },
      },
    },
  },
})
```

### 4.6 Safe `<NuxtLink>` Usage

```vue
<!-- ✅ SECURE — Validate URLs before binding to NuxtLink -->
<script setup>
const props = defineProps(['userProvidedUrl'])

function safeUrl(url) {
  if (!url) return '/'
  try {
    const parsed = new URL(url)
    if (parsed.protocol === 'javascript:' || parsed.protocol === 'vbscript:') {
      return '/'
    }
    return url
  } catch {
    return '/'
  }
}
</script>

<template>
  <!-- ✅ URL is sanitized — prevents CVE-2026-53722 -->
  <NuxtLink :to="safeUrl(userProvidedUrl)">Click here</NuxtLink>
</template>
```

### 4.7 Safe External Navigation

```vue
<script setup>
// ✅ SECURE — Validate external URLs and use server-side redirect
const navigateToExternal = (url) => {
  // Reject javascript: and data: URLs
  const allowedProtocols = ['http:', 'https:', 'mailto:']

  try {
    const parsed = new URL(url)
    if (!allowedProtocols.includes(parsed.protocol)) {
      console.error('Blocked navigation to:', url)
      return
    }
    // Use server-side 302 redirect rather than client-side meta refresh
    navigateTo(url, { external: true, redirectCode: 302 })
  } catch {
    console.error('Invalid URL:', url)
  }
}
</script>
```

---

## 5. Real CVEs

### 5.1 CVE-2026-53721 — Nuxt Route-Rule Middleware Bypass

| Field | Value |
|-------|-------|
| **CVSS** | 8.2 (High) |
| **CWE** | CWE-178 (Case Sensitivity), CWE-863 (Incorrect Authorization) |
| **Affected** | Nuxt 3.11.0–3.21.6, 4.0.0–4.4.6 |
| **Fixed In** | 3.21.7, 4.4.7 |
| **Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N |

**Description:** Case-sensitivity mismatch between `vue-router` and the `routeRules` matcher. An attacker can access protected routes (e.g., `/Admin` instead of `/admin`) that bypass middleware checks when `routeRules` are used.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-53721

---

### 5.2 CVE-2026-47200 — Island Route Middleware Bypass

| Field | Value |
|-------|-------|
| **CVSS** | 5.3 (Medium) |
| **CWE** | CWE-284 (Improper Access Control) |
| **Affected** | Nuxt 3.11.0–3.21.5, 4.0.0-alpha.1–4.4.5 |
| **Fixed In** | 3.21.6, 4.4.6 |

**Description:** When `experimental.componentIslands` is enabled (default in Nuxt 4), `.server.vue` page files are accessible via `/__nuxt_island/page_*` endpoints that render pages without instantiating Vue Router — route middleware declared with `definePageMeta({ middleware })` never runs. An unauthenticated attacker can request these endpoints directly.

**Source:** https://github.com/nuxt/nuxt/security/advisories/GHSA-hg3f-28rg-4jxj

---

### 5.3 CVE-2026-45669 — Reflected XSS via navigateTo

| Field | Value |
|-------|-------|
| **CVSS** | 5.4 (Medium) |
| **CWE** | CWE-79 (XSS) |
| **Affected** | Nuxt 3.4.3–3.21.5, 4.0.0-alpha.1–4.4.5 |
| **Fixed In** | 3.21.6, 4.4.6 |

**Description:** `navigateTo({ external: true })` generates a server-side HTML redirect with `<meta http-equiv="refresh">` containing an unencoded destination URL. Only `"` is replaced with `%22`, leaving `<`, `>`, `&`, and `'` unencoded — allowing HTML/JavaScript injection.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-45669

---

### 5.4 CVE-2026-46342 — Island Cache Poisoning

| Field | Value |
|-------|-------|
| **CVSS** | 5.4 (Medium) |
| **CWE** | CWE-346 (CORS), CWE-345 (Insufficient Verification) |
| **Affected** | Nuxt 3.1.0–3.21.5, 4.0.0-alpha.1–4.4.5 |
| **Fixed In** | 3.21.6, 4.4.6 |

**Description:** The `/__nuxt_island/*` endpoint accepts attacker-controlled props via query/body parameters without server-side hash validation. The same path returns different content depending on query parameters, enabling cache poisoning and XSS when those props reach unsafe HTML sinks.

**Source:** https://github.com/nuxt/nuxt/security/advisories/GHSA-g8wj-3cr3-6w7h

---

### 5.5 CVE-2025-24360 — Nuxt Dev Server CORS Source Theft

| Field | Value |
|-------|-------|
| **CVSS** | 5.3 (Medium) |
| **CWE** | CWE-346 (Origin Validation Error) |
| **Affected** | Nuxt 3.8.1–3.15.2 (Vite builder) |
| **Fixed In** | 3.15.3 |

**Description:** Default CORS settings in Nuxt's dev server allow any website to send requests and read responses. An attacker can steal source code by luring a developer to visit a malicious site while the dev server is running.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-24360

---

### 5.6 CVE-2025-27415 — Nuxt CDN Cache Poisoning

| Field | Value |
|-------|-------|
| **CVSS** | 7.5 (High) |
| **CWE** | CWE-349 (Acceptance of Extraneous Untrusted Data) |
| **Affected** | Nuxt < 3.16.0 |
| **Fixed In** | 3.16.0 |

**Description:** Sending a crafted request like `https://mysite.com/?/\_payload.json` renders as JSON. If the CDN ignores the query string when caching, the JSON response is served to all visitors — enabling permanent site-wide denial of service.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-27415

---

### 5.7 CVE-2026-56317 — Nuxt NoScript XSS

| Field | Value |
|-------|-------|
| **Affected** | Nuxt < 3.21.7, < 4.4.7 |
| **Fixed In** | 3.21.7, 4.4.7 |

**Description:** The NoScript component writes slot content to `innerHTML` without escaping. Attackers can inject malicious scripts through untrusted data in NoScript slots (e.g., `route.query`), which execute when the `<noscript>` tag is implicitly closed by `<script>` tags.

**Source:** https://app.opencve.io/cve/CVE-2026-56317

---

### 5.8 CVE-2026-53722 — NuxtLink XSS via javascript: URLs

| Field | Value |
|-------|-------|
| **CVSS** | 5.4 (Medium) |
| **Affected** | Nuxt < 3.21.7, < 4.4.7 |
| **Fixed In** | 3.21.7, 4.4.7 |

**Description:** `<NuxtLink>` does not validate the URL scheme of values bound to `to` or `href` props. An attacker can supply `javascript:` or `vbscript:` URLs that render verbatim into the `<a>` element's `href` attribute — clicking the link executes the supplied script in the application's origin.

**Source:** https://app.opencve.io/cve/CVE-2026-53722

---

### 5.9 CVE-2024-6783 — Vue.js XSS via Prototype Pollution

| Field | Value |
|-------|-------|
| **CVSS** | 4.8 (Medium) |
| **CWE** | CWE-79 (XSS) |
| **Affected** | Vue 2.0.0–3.4.x (full build with template compiler) |
| **Fixed In** | Not yet publicly patched (use runtime-only build) |

**Description:** An attacker can manipulate the prototype chain of template-compiler properties such as `Object.prototype.staticClass` or `Object.prototype.staticStyle` to execute arbitrary JavaScript through the Vue template compiler.

**Mitigation:** Use the runtime-only build of Vue (`vue.runtime.*`) which excludes the template compiler. This is the default in Vue CLI / Vite scaffolded projects.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-6783

---

### 5.10 CVE-2024-23657 — Nuxt Devtools Path Traversal → RCE

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (High) |
| **CWE** | CWE-22 (Path Traversal) |
| **Affected** | `@nuxt/devtools` < 1.3.9 |
| **Fixed In** | 1.3.9 |

**Description:** Missing authentication on the `getTextAssetContent` RPC function combined with no Origin check on the WebSocket handler allows cross-site WebSocket hijacking. An attacker can read arbitrary files (path traversal), discover the auth token, then use `writeStaticAssets` to create malicious components that execute automatically.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-23657

---

### 5.11 CVE-2023-3224 — Nuxt Code Injection

| Field | Value |
|-------|-------|
| **CVSS** | 9.8 (Critical) |
| **CWE** | CWE-94 (Code Injection) |
| **Affected** | Nuxt < 3.5.3 |
| **Fixed In** | 3.5.3 |

**Description:** Code injection vulnerability in the Nuxt framework allowing unauthenticated remote code execution. This is a foundational framework vulnerability — ensure Nuxt is on the latest version.

**Source:** https://app.opencve.io/cve/CVE-2023-3224

---

### CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2023-3224 | 9.8 | Nuxt < 3.5.3 | Code Injection | 3.5.3 |
| CVE-2024-23657 | 8.8 | @nuxt/devtools < 1.3.9 | Path Traversal → RCE | 1.3.9 |
| CVE-2024-34344 | 8.8 | Nuxt (test) | RCE via TestComponentWrapper | 3.13.0 |
| CVE-2026-53721 | 8.2 | Nuxt 3.11–3.21.6, 4.0–4.4.6 | Middleware Bypass | 3.21.7 / 4.4.7 |
| CVE-2025-27415 | 7.5 | Nuxt < 3.16.0 | CDN Cache Poisoning | 3.16.0 |
| CVE-2026-56326 | 6.1 | Nuxt < 3.21.7, < 4.4.7 | Open Redirect | 3.21.7 / 4.4.7 |
| CVE-2026-56698 | 6.1 | Nuxt < 3.21.7, < 4.4.7 | XSS via navigateTo open | 3.21.7 / 4.4.7 |
| CVE-2026-45669 | 5.4 | Nuxt 3.4.3–3.21.5 | Reflected XSS (navigateTo) | 3.21.6 / 4.4.6 |
| CVE-2026-46342 | 5.4 | Nuxt 3.1–3.21.5 | Island Cache Poisoning | 3.21.6 / 4.4.6 |
| CVE-2026-53722 | 5.4 | Nuxt < 3.21.7, < 4.4.7 | NuxtLink XSS | 3.21.7 / 4.4.7 |
| CVE-2026-47200 | 5.3 | Nuxt 3.11–3.21.5 | Island Middleware Bypass | 3.21.6 / 4.4.6 |
| CVE-2025-24360 | 5.3 | Nuxt 3.8.1–3.15.2 | CORS Source Theft | 3.15.3 |
| CVE-2025-24361 | 5.3 | Nuxt 3.0–3.15.12 (webpack/rspack) | Source Code Theft | 3.15.13 |
| CVE-2024-6783 | 4.8 | Vue 2.0–3.4 (full build) | XSS via Prototype Pollution | Use runtime build |

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

## Verification / Source URLs

- NVD CVE-2026-53721: https://nvd.nist.gov/vuln/detail/CVE-2026-53721
- NVD CVE-2026-45669: https://nvd.nist.gov/vuln/detail/CVE-2026-45669
- NVD CVE-2026-47200 (via GitHub Advisory): https://github.com/nuxt/nuxt/security/advisories/GHSA-hg3f-28rg-4jxj
- NVD CVE-2026-46342 (via GitHub Advisory): https://github.com/nuxt/nuxt/security/advisories/GHSA-g8wj-3cr3-6w7h
- NVD CVE-2025-24360: https://nvd.nist.gov/vuln/detail/CVE-2025-24360
- NVD CVE-2025-27415: https://nvd.nist.gov/vuln/detail/CVE-2025-27415
- NVD CVE-2024-6783: https://nvd.nist.gov/vuln/detail/CVE-2024-6783
- NVD CVE-2024-23657: https://nvd.nist.gov/vuln/detail/CVE-2024-23657
- NVD CVE-2025-24361: https://nvd.nist.gov/vuln/detail/CVE-2025-24361
- OpenCVE Nuxt CVEs: https://app.opencve.io/cve/?product=nuxt&vendor=nuxt
- Nuxt Security Advisories: https://github.com/nuxt/nuxt/security
- Nuxt Security Module: https://github.com/Baroshem/nuxt-security
- Vue Security Guide: https://vuejs.org/guide/best-practices/security
- Netlify Nuxt CVE Analysis (2026-05-19): https://www.netlify.com/changelog/2026-05-19-nuxt-security-vulnerabilities/
- Ionix CVE-2026-53721 Analysis: https://www.ionix.io/threat-center/cve-2026-53721/
- Nuxt Runtime Config Docs: https://nuxt.com/docs/getting-started/runtime-config
- SentinelOne CVE-2025-24361: https://www.sentinelone.com/vulnerability-database/cve-2025-24361/
