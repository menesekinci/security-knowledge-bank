---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
category: "language-vuln"
language: "javascript"
chunk: 5
total_chunks: 11
heading: "Attack Vector 3: Scoped Import Hijacking"
---

## Attack Vector 3: Scoped Import Hijacking

### The Problem

Import maps support **scope** — different mappings for different URL paths. If an attacker can craft a URL that falls under a different scope than expected, they can hijack module resolution.

```html
<script type="importmap">
{
  "imports": {
    "helper": "/js/helper.js"
  },
  "scopes": {
    "/admin/": {
      "helper": "https://trusted-cdn.com/admin-helper.js"
    }
  }
}
</script>
```

### Exploitation

An attacker who can control part of the URL path (e.g., via path traversal or routing quirks) can cause a page to fall under a different scope:

```javascript
// If attacker can navigate user to:
// https://example.com/admin/../../../user-page/
// The module resolution for "helper" switches to admin scope
// This could load a different version than intended
```

### Secure Scoping

```html
<script type="importmap">
{
  "imports": {
    "helper": "/js/helper.js"
  },
  "scopes": {
    "/admin/": {
      "helper": "/js/helper.js"  // Same module as default
    }
  }
}
</script>
```

---