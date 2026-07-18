---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Attack Vector 6: CDN Trust and Dependency Confusion"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 8/11
---

## Attack Vector 6: CDN Trust and Dependency Confusion

### The Problem

Import maps often point to public CDNs. Module specifiers without a registry source can be confused with other modules, similar to npm dependency confusion.

```html
<script type="importmap">
{
  "imports": {
    "lodash": "/js/lodash.js",  // Local copy — safe
    "lodash-fp": "https://unpkg.com/lodash-fp@1.0.0",  // CDN — trust risk
    "my-internal-util": "/js/util.js",  // Internal — could conflict with public
  }
}
</script>
```

### Escalation to Dependency Confusion

If an attacker publishes a package named `my-internal-util` to a public registry, and a developer accidentally removes the local mapping, the module could resolve to a different location.

### Secure Pattern

```html
<script type="importmap">
{
  "imports": {
    // Always map ALL module specifiers explicitly
    "lodash": "/vendor/lodash-4.17.21.js",
    "lodash-fp": "/vendor/lodash-fp-1.0.0.js",
    "my-internal-util": "/js/util.js",
    // Scope CDN URLs with integrity hashes
    "react": "https://cdn.example.com/react@18.2.0.js"
  },
  "integrity": {
    "https://cdn.example.com/react@18.2.0.js": "sha384-abc123..."
  }
}
</script>
```

---