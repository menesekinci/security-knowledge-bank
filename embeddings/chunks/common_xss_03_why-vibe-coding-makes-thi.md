---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

AI code generators frequently produce XSS-vulnerable code because:

- **AI defaults to inline HTML rendering:** React's `dangerouslySetInnerHTML`, Vue's `v-html`, and raw `innerHTML` assignments are common AI outputs
- **Template engines without auto-escaping:** AI may generate Handlebars/ERB templates without `{{{{ }}}}` escaping
- **Forgotten output encoding:** AI focuses on data flow but misses the encoding step at the output boundary
- **CSP headers omitted:** Security headers are "overhead" the AI skips unless explicitly prompted
- **`eval()` for convenience:** Dynamic code execution in responses

---