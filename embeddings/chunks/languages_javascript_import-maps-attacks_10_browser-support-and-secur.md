---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Browser Support and Security Status"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 10/11
---

## Browser Support and Security Status

| Browser | Import Maps | CSP Enforcement | Integrity Support |
|---------|------------|-----------------|-------------------|
| Chrome 89+ | ✅ Full | ✅ Since ~Chrome 95 | ❌ Not yet |
| Firefox 108+ | ✅ Full | ✅ | ❌ Not yet |
| Safari 16.4+ | ✅ Full | ✅ | ❌ Not yet |
| Edge 89+ | ✅ Full (Chromium) | ✅ | ❌ Not yet |

> **Note:** Integrity support in import maps is an emerging proposal. Use tools like `@jspm/generator` to generate integrity values in the interim.

---