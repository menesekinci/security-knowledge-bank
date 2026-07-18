---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] NEVER use `innerHTML`, `outerHTML`, `insertAdjacentHTML('beforeend', ...)`, or `document.write()` with user input
- [ ] Use `textContent` instead of `innerHTML` — it's the safest alternative
- [ ] In React, avoid `dangerouslySetInnerHTML` — if necessary, sanitize with DOMPurify first
- [ ] In Vue, use `v-text` instead of `v-html`
- [ ] Sanitize ALL HTML with DOMPurify before any HTML insertion into DOM
- [ ] Set strict Content Security Policy headers
- [ ] Never put user input in `<script>` tags, `on*` attributes, or `href="javascript:..."` 
- [ ] Use `encodeURIComponent()` for URL parameters, `encodeURI()` for full URLs
- [ ] For rich text, use markdown (with a safe parser like `marked` with sanitization) instead of raw HTML
- [ ] Validate URLs: reject `javascript:`, `data:`, `vbscript:` protocols
- [ ] Use Trusted Types API (Chrome) for granular DOM injection control

---