---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Attack Vector 5: Bare Specifier Sniffing"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 7/11
---

## Attack Vector 5: Bare Specifier Sniffing

### The Problem

The structure of import maps can reveal information about the application's internal module organization. Attackers can use this to:

1. Identify private module names
2. Discover internal URL structures
3. Find unreleased or internal-only modules

### Information Leak

```html
<!-- The import map reveals internal module structure -->
<script type="importmap">
{
  "imports": {
    "@internal/auth": "/internal/auth.js",
    "@internal/admin-panel": "/admin/v2/app.js",
    "@internal/beta-feature": "/beta/experimental.js"
  }
}
</script>
```

### Secure Import Map

```javascript
// Minimize information in import maps
// Use URL shorteners or version-encoded paths
<script type="importmap">
{
  "imports": {
    "@app/main": "/js/a1b2c3.js",  // Hashed, descriptive names removed
    "@app/auth": "/js/d4e5f6.js",
    "@app/admin": "/js/g7h8i9.js"
  }
}
</script>
```

---