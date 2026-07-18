---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "2. How AI Generates These Vulnerabilities"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 4/10
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