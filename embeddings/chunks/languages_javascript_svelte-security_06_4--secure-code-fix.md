---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "4. Secure Code Fix"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 6/10
---

## 4. Secure Code Fix

### 4.1 Safe HTML Rendering

```svelte
<!-- ✅ SECURE — Escape HTML, don't render raw user content -->
<script>
  import { escape } from 'svelte/internal'; // or use DOMPurify

  let userContent = $state(htmlInput);

  // Option 1: Escape HTML entirely
  let escapedContent = $derived(escape(userContent));

  // Option 2: Sanitize with DOMPurify (only for trusted HTML subsets)
  import DOMPurify from 'dompurify';
  let sanitizedContent = $derived(DOMPurify.sanitize(userContent));
</script>

<!-- Use regular interpolation (auto-escaped) -->
<p>{userContent}</p>

<!-- Or sanitized {@html} with explicit DOMPurify -->
<p>{@html sanitizedContent}</p>
```

### 4.2 Authenticated Endpoints

```javascript
// ✅ SECURE — src/routes/api/users/+server.js
import { json, error } from '@sveltejs/kit';

// Apply to ALL server endpoints
export async function GET({ locals, url }) {
  // Always check authentication
  if (!locals.user) {
    throw error(401, 'Authentication required');
  }

  // Check authorization
  if (locals.user.role !== 'admin') {
    throw error(403, 'Insufficient permissions');
  }

  // Only select needed fields — never expose passwordHash
  const users = await prisma.user.findMany({
    select: { id: true, name: true, email: true, createdAt: true }
  });

  return json(users);
}
```

### 4.3 Validated Form Actions

```javascript
// ✅ SECURE — src/routes/register/+page.server.js
import { fail } from '@sveltejs/kit';

export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    const email = data.get('email');
    const password = data.get('password');
    const name = data.get('name');

    // Validate every field explicitly — NEVER use Object.fromEntries()
    if (!email || typeof email !== 'string') {
      return fail(400, { error: 'Email is required' });
    }
    if (!password || typeof password !== 'string' || password.length < 8) {
      return fail(400, { error: 'Password must be at least 8 characters' });
    }

    // Whitelist approach — only specific fields
    const user = await db.user.create({
      data: {
        email: email.toLowerCase().trim(),
        passwordHash: await hash(password),
        name: name?.toString().trim() || 'User',
        isAdmin: false // 💀 Never accept from form data
      }
    });

    return { success: true };
  }
};
```

### 4.4 CSRF Protection (SvelteKit 1.15.2+)

```javascript
// ✅ SECURE — svelte.config.js (updated)
const config = {
  kit: {
    csrf: {
      checkOrigin: true, // Enabled by default
      // Content-Type validation now includes text/plain
      // and case-insensitive header checking
    }
  }
};

// ✅ Also — Use SameSite=Strict/Lax for session cookies
// In hooks.server.js:
export const handle = async ({ event, resolve }) => {
  // Ensure SameSite is set
  const response = await resolve(event);
  response.headers['Set-Cookie'] = response.headers['Set-Cookie']
    ?.replace('SameSite=Lax', 'SameSite=Strict');
  return response;
};
```

### 4.5 Secure Server Load Functions

```javascript
// ✅ SECURE — src/routes/admin/+page.server.js
export async function load({ locals }) {
  if (!locals.user || locals.user.role !== 'admin') {
    throw redirect(303, '/login');
  }

  const adminData = await db.admin.findUnique({
    where: { id: locals.user.id },
    select: {
      // Explicit select — only fields needed on client
      id: true,
      name: true,
      email: true,
      lastLogin: true
      // 💀 passwordHash, secretKey omitted
    }
  });

  return { adminData };
}
```

### 4.6 Auth Guard in `hooks.server.js`

```javascript
// ✅ SECURE — src/hooks.server.js
import { redirect } from '@sveltejs/kit';

const protectedRoutes = ['/admin', '/dashboard', '/settings'];
const authRoutes = ['/login', '/register'];

export const handle = async ({ event, resolve }) => {
  const { url, locals, cookies } = event;

  // Set up session
  const session = cookies.get('session');
  locals.user = await getSessionUser(session); // Validate server-side

  // Protect routes
  if (protectedRoutes.some(p => url.pathname.startsWith(p))) {
    if (!locals.user) {
      throw redirect(303, '/login');
    }
  }

  // Redirect authenticated users away from auth pages
  if (authRoutes.some(p => url.pathname.startsWith(p))) {
    if (locals.user) {
      throw redirect(303, '/dashboard');
    }
  }

  const response = await resolve(event);

  // Security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Content-Security-Policy',
    "script-src 'self'; object-src 'none'");

  return response;
};
```

---