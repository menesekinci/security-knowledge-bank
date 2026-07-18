---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 5/10
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