---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Types of XSS"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 4/10
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