---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "6. Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 8/10
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