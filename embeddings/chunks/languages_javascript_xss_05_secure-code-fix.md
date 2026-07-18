---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "Secure Code Fix"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: Use textContent Instead of innerHTML (Vanilla JS)

```javascript
// ✅ SAFE — Use textContent
function displayUserComment(comment) {
  const container = document.getElementById('comments');
  const div = document.createElement('div');
  div.className = 'comment';
  
  const p = document.createElement('p');
  p.textContent = comment.text;  // ✅ No HTML parsing
  
  const small = document.createElement('small');
  small.textContent = comment.author;  // ✅ No HTML parsing
  
  div.appendChild(p);
  div.appendChild(small);
  container.appendChild(div);
}
```

### Fix 2: Sanitize with DOMPurify Before innerHTML

```javascript
// ✅ SAFE — Sanitize HTML before insertion
import DOMPurify from 'dompurify';

function displayUserComment(comment) {
  const sanitized = DOMPurify.sanitize(comment.text);  // ✅ Strips dangerous tags
  document.getElementById('comments').innerHTML += `
    <div class="comment">
      <p>${sanitized}</p>
    </div>
  `;
}
```

### Fix 3: React — Don't Use dangerouslySetInnerHTML

```javascript
// ✅ SAFE — React with proper escaping
function UserProfile({ bio }) {
  // React auto-escapes by default
  return (
    <div className="profile-bio">
      {bio}  {/* ✅ Automatically escaped — no XSS */}
    </div>
  );
}

// If you MUST render HTML (e.g., markdown output):
import DOMPurify from 'dompurify';

function SafeRichContent({ html }) {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: DOMPurify.sanitize(html)  // ✅ Sanitized
      }}
    />
  );
}
```

### Fix 4: Vue.js — Use v-text Instead of v-html

```vue
<!-- ✅ SAFE — Vue with v-text -->
<template>
  <div v-text="userContent"></div>  <!-- ✅ Auto-escaped -->
</template>
```

### Fix 5: Encode Context Properly

```javascript
// ✅ SAFE — Encode for different contexts
function encodeForHTML(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

function encodeForAttribute(str) {
  return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;')
            .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function encodeForURL(str) {
  return encodeURIComponent(str);
}

// Usage
element.innerHTML = `<a href="${encodeForAttribute(url)}">${encodeForHTML(text)}</a>`;
```

### Fix 6: Content Security Policy (Defense in Depth)

```html
<!-- ✅ SAFE — CSP headers prevent XSS even if injection occurs -->
<!-- In HTTP response header: -->
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

<!-- Or in meta tag: -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'; object-src 'none'">
```

---