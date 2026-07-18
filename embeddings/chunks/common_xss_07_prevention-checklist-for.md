---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 7/10
---

## Prevention Checklist for AI Prompts

```
✅ XSS PREVENTION FOR THIS CODE:
- Use context-aware output encoding for ALL user-controlled data
- NEVER use innerHTML, dangerouslySetInnerHTML, v-html, or similar APIs
- Use textContent, innerText, or framework's automatic escaping
- Set strict Content-Security-Policy headers (nonce-based)
- Sanitize HTML on the server side before storing (allowlist approach)
- Validate input type and length on both client and server
- Use DOMPurify if HTML rendering is absolutely required
- Set HttpOnly and Secure flags on session cookies
- Never put untrusted data in <script>, <style>, or event handler attributes
- X-XSS-Protection: 0 (modern browsers disable XSS auditor; rely on CSP)
```

### Quick Decision Tree

```
User data goes into output?
├── HTML body → HTML-entity encode
├── HTML attribute → Attribute encode + quote wrapping
├── <script> / JS string → NEVER put untrusted data here
├── URL parameter → URL encode
├── CSS value → Avoid entirely
└── Safe (React/Vue/Svelte JSX/template) → Framework auto-escapes, but watch for v-html/dangerouslySetInnerHTML
```

---