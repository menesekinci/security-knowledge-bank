---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Attack Vector 2: Module Integrity Bypass"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 4/11
---

## Attack Vector 2: Module Integrity Bypass

### The Problem

Unlike `<script src="..." integrity="sha384-...">`, import maps in their initial implementation had **no integrity checking** for resolved modules. An attacker who compromises a CDN or intercepts traffic can serve malicious module content.

### Vulnerable Pattern

```html
<!-- No integrity checking on the resolved module URL -->
<script type="importmap">
{
  "imports": {
    "lodash": "https://cdn.example.com/lodash@4.17.21.js"
  }
}
</script>

<!-- If cdn.example.com is compromised, lodash becomes malicious -->
<!-- The browser has no way to verify the module hasn't been tampered with -->
```

### The Fix: Import Map Integrity

**Source:** https://jspm.org/js-integrity-with-import-maps

The Web App Secure Module Integrity proposal (and JSPM's implementation) adds an `integrity` field to import maps:

```html
<script type="importmap">
{
  "imports": {
    "lodash": "https://cdn.example.com/lodash@4.17.21.js"
  },
  "integrity": {
    "https://cdn.example.com/lodash@4.17.21.js": "sha384-ABC123..."
  }
}
</script>
```

### Implementing Integrity in Your Import Maps

```javascript
// Generate integrity hashes for import map modules
const crypto = require('crypto');
const https = require('https');

async function generateImportMap(deps) {
  const integrity = {};
  const imports = {};
  
  for (const [name, url] of Object.entries(deps)) {
    const hash = await fetchIntegrityHash(url);
    imports[name] = url;
    integrity[url] = `sha384-${hash}`;
  }
  
  return JSON.stringify({ imports, integrity }, null, 2);
}

async function fetchIntegrityHash(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      const hash = crypto.createHash('sha384');
      response.on('data', (chunk) => hash.update(chunk));
      response.on('end', () => resolve(hash.digest('base64')));
    }).on('error', reject);
  });
}
```

---