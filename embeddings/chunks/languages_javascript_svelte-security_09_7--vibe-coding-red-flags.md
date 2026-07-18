---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "7. Vibe-Coding Red Flags (Svelte/SvelteKit-Specific)"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 9/10
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