---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
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