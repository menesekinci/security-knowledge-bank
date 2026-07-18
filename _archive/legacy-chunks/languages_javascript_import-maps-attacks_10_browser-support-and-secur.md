---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
category: "language-vuln"
language: "javascript"
chunk: 10
total_chunks: 11
heading: "Browser Support and Security Status"
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