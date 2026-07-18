---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "2. How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 4/10
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