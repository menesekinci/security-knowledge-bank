---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
heading: "Real-World CVEs"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-29650** | Prototype pollution in popular JS library (2024) | Affected multiple downstream apps |
| **CVE-2023-26136** | `tough-cookie` < 4.1.3 — pollution via `CookieJar` in `rejectPublicSuffixes=false` mode | Prototype pollution (CVSS 9.8) |
| **CVE-2022-46175** | `json5` — `parse()` fails to block `__proto__` keys (< 1.0.2, 2.0.0–2.2.1) | Prototype pollution → DoS/XSS/RCE (CVSS 8.8) |
| **CVE-2021-3918** | `json-schema` <= 0.3.0 prototype pollution | Widely bundled; affected many downstream deps (CVSS 9.8) |
| **CVE-2020-8203** | `lodash` < 4.17.20 — pollution via `_.zipObjectDeep` | Prototype pollution → DoS/RCE (CVSS 7.4) |
| **CVE-2020-28273** | `set-in` 1.0.0–2.0.0 — property setter prototype pollution | DoS, potentially RCE (CVSS 9.8) |
| **CVE-2019-10744** | `lodash.merge` / `_.defaultsDeep` prototype pollution | Affected all lodash versions before 4.17.12 |
| **CVE-2018-3721** | lodash `_.merge` / `_.defaultsDeep` (< 4.17.5) | Original lodash pollution CVE |

### Real-World Exploitation

Prototype pollution has been exploited in the wild to:

- **Bypass authentication** — Pollute `isAdmin`, `authenticated`, `role` properties
- **Bypass authorization** — Pollute `canDelete`, `canEdit` permission checks
- **Inject XSS** — Pollute DOM element properties that map to event handlers
- **Bypass sanitization** — Pollute validation library configs
- **Defeat CSP** — Pollute CSP configuration objects

---