---
source: "languages/javascript/dom-clobbering.md"
title: "DOM Clobbering Attacks in Modern Frameworks"
category: "language-vuln"
language: "javascript"
chunk: 2
total_chunks: 9
heading: "Overview"
---

## Overview

DOM Clobbering is a code-reuse attack where seemingly benign HTML elements (like `<img>` tags with `name` or `id` attributes) "clobber" (overwrite) DOM properties that JavaScript relies on. By injecting non-script HTML, an attacker can alter global variables (`window` properties), `document` references, and even the behavior of modern build tooling.

### How DOM Clobbering Works

```javascript
// Without DOM clobbering:
console.log(window.someVariable);  // undefined

// With DOM clobbering — inject:
// <a id="someVariable" href="http://evil.com/data">
console.log(window.someVariable);  // <a> element
console.log(window.someVariable.href);  // "http://evil.com/data"
```

The browser's named access on the `Window` object means every element with an `id` or `name` attribute becomes accessible as a `window` property.

---