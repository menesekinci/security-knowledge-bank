---
source: "languages/javascript/index.md"
title: "JavaScript Security — Overview"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [critical, cves, file, index, javascript, language-vuln]
---

# JavaScript Security — Overview

> **Audience:** Developers using AI-assisted coding who need to understand JS-specific security pitfalls.
> **Target:** Vibe Coding security knowledge base — practical, actionable, CVE-backed.

---

## The JavaScript Security Landscape

JavaScript powers both the frontend (browser) and backend (Node.js) of modern web applications. This dual role creates a uniquely broad attack surface — DOM-based attacks on one side, server-side attacks on the other. AI coding assistants generate JavaScript code more than any other language, and the patterns they produce are riddled with security pitfalls.

### Why JavaScript Is a Security Minefield in AI-Generated Code

1. **Dynamic typing with prototype-based inheritance:** `__proto__`, `constructor.prototype`, and object mutation create unique attack vectors (prototype pollution) that don't exist in class-based languages.

2. **The npm ecosystem is the largest package registry:** Over 2 million packages, with minimal vetting. AI models frequently generate `npm install` commands with no integrity verification.

3. **Browser APIs are dangerously powerful:** `innerHTML`, `document.write()`, `eval()` equivalents, and `localStorage` all appear in AI training data without security context.

4. **JWT is everywhere:** AI models generate authentication code using JWT but often misconfigure the `alg` field, use weak secrets, or skip signature verification.

5. **SSRF is rampant in Node.js:** AI-generated code freely passes user-provided URLs to `fetch()`, `axios.get()`, and `http.get()`.

### The Vibe Coding Factor

AI code generators for JavaScript have specific failure modes:

- **React `dangerouslySetInnerHTML` is used without sanitization** — AI knows the API name but not how to use it safely
- **`innerHTML` is preferred over `textContent`** — AI training data contains more innerHTML examples
- **`eval()` and `new Function()` appear in "creative" solutions** — AI reaches for dynamic execution
- **npm packages are installed without `--save-exact` or lockfiles** — AI assumes latest versions are safe
- **`Math.random()` used for tokens, IDs, and "randomization"** — AI doesn't know it's predictable

### Top JavaScript Security Findings in AI-Generated Code

| Vulnerability | Location | Severity |
|---|---|---|
| DOM-based XSS | Frontend (React, Vue, vanilla) | Critical |
| Prototype pollution | Frontend + Backend | Critical |
| npm supply chain | Build/deploy | Critical |
| `eval()` / `new Function()` | Backend (Node.js) | Critical |
| JWT algorithm confusion | Backend (Auth) | Critical |
| SSRF in Node.js | Backend (API) | High |
| Weak crypto (Math.random) | Anywhere | High |
| Insecure `innerHTML` | Frontend | High |

---

## Critical CVEs Relevant to JS AI-Generated Code

| CVE | Description | Relevance |
|---|---|---|
| **CVE-2024-39338** | Axios SSRF — path relative URL handling bypass | HTTP client vulnerability |
| **CVE-2024-29650** | Prototype pollution in popular JS library | Widespread POLL risk |
| **CVE-2024-54150** | JWT algorithm confusion in cjwt library | Auth bypass |
| **CVE-2024-24806** | Node.js HTTP library SSRF | Server-side request forgery |
| **CVE-2024-29415** | `ip` package SSRF (Node.js) | IP address validation bypass |

---

## File Index

| File | Topic |
|---|---|
| `xss.md` | DOM-based XSS, innerHTML, dangerouslySetInnerHTML |
| `prototype-pollution.md` | Prototype pollution deep dive |
| `npm-supply-chain.md` | Malicious packages, dependency confusion, script injection |
| `eval-injection.md` | eval(), new Function(), setTimeout string |
| `crypto-mistakes.md` | Web Crypto API misuse, Math.random() for crypto |
| `jwt-misuse.md` | JWT alg:none, weak secret, missing verification |
| `ssrf-node.md` | Server-side request forgery in Node.js |

---

*Last updated: July 2026 — CVEs and patterns reflect current threat landscape.*
