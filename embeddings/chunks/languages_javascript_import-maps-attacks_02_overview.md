---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Overview"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 2/11
---

## Overview

Import maps are a browser-native mechanism for controlling how JavaScript modules are resolved. Defined via a `<script type="importmap">` tag, they allow developers to specify URL mappings for bare module specifiers:

```html
<script type="importmap">
{
  "imports": {
    "lodash": "/node_modules/lodash-es/lodash.js",
    "react": "https://cdn.example.com/react@18.2.0/index.js"
  }
}
</script>
```

While powerful, import maps introduce unique security risks: they create a new capability that **bypasses traditional CSP controls**, can **redirect modules to attacker-controlled URLs**, and have **no built-in integrity verification** in the initial specification.

---