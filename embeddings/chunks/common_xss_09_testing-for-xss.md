---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Testing for XSS"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 9/10
---

## Testing for XSS

**Manual testing payloads:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
javascript:alert(1)
<svg/onload=alert(1)>
'"><img src=x onerror=alert(1)>
```

**Automated tools:**
- [XSStrike](https://github.com/s0md3v/XSStrike) — Advanced XSS detection
- [DOMPurify](https://github.com/cure53/DOMPurify) — HTML sanitizer library
- Browser DevTools — Network tab to inspect response payloads

---