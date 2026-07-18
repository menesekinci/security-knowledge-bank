---
source: "languages/javascript/dom-clobbering.md"
title: "DOM Clobbering Attacks in Modern Frameworks"
category: "language-vuln"
language: "javascript"
chunk: 8
total_chunks: 9
heading: "DOM Clobbering Gadget Detection"
---

## DOM Clobbering Gadget Detection

### Automated Detection

```javascript
// Scan for vulnerable patterns
function detectDOMClobberingGadgets() {
  const vulnerablePatterns = [
    'document.currentScript',
    'document.getElementById(',
    'window.',
    'self.',
    'globalThis.'
  ];
  // ... scan bundles for these patterns
}
```

### Manual Code Review Checklist

| Pattern | Risk Level | Example |
|---------|-----------|---------|
| `document.currentScript.src` | 🔴 Critical | Vite/Rollup CVE pattern |
| `window[userControlled]` | 🔴 Critical | Direct property access |
| `document.getElementById(id)` with tainted `id` | 🟡 High | Service worker attacks |
| Global variable without `let/const/var` | 🟡 High | Implicit globals |
| `if (someVar)` without `undefined` check | 🟡 Medium | Falsy values clobbered |
| `typeof` checks | 🟢 Low | `typeof` is immune |

---