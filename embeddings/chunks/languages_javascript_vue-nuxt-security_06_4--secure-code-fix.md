---
source: "languages/javascript/vue-nuxt-security.md"
title: "Vue.js & Nuxt Security Deep Dive"
heading: "4. Secure Code Fix"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 6/10
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