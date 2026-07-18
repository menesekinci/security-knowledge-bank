---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 7
total_chunks: 8
heading: "Real-World CVEs"
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-29650** | Prototype pollution in popular JS library (2024) | Affected multiple downstream apps |
| **CVE-2023-26118** | `angular` merge utility prototype pollution | Angular apps before 1.8.3 |
| **CVE-2023-26136** | `flat` and `unflatten` npm packages | Recursive merge with pollution |
| **CVE-2022-25881** | `http-cache-semantics` prototype pollution | HTTP caching middleware |
| **CVE-2021-25939** | `deepmerge` npm package (before 4.2.2) | Merge function pollution |
| **CVE-2020-28273** | `set-value` npm package (before 4.0.1) | Property setter pollution |
| **CVE-2019-10744** | `lodash.merge` prototype pollution | Affected all lodash versions before 4.17.12 |
| **CVE-2018-3721** | lodash `_.merge` / `_.defaultsDeep` | Original lodash pollution CVE |

### Real-World Exploitation

Prototype pollution has been exploited in the wild to:

- **Bypass authentication** — Pollute `isAdmin`, `authenticated`, `role` properties
- **Bypass authorization** — Pollute `canDelete`, `canEdit` permission checks
- **Inject XSS** — Pollute DOM element properties that map to event handlers
- **Bypass sanitization** — Pollute validation library configs
- **Defeat CSP** — Pollute CSP configuration objects

---