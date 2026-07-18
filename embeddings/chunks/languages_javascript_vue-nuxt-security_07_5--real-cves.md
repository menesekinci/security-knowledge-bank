---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "5. Real CVEs"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 7/10
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