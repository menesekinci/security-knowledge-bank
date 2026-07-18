---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 9/11
---

## Prevention Checklist

| Issue | Risk | Mitigation |
|-------|------|-----------|
| CSP bypass via import map injection | 🔴 Critical | Nonce-based CSP for all `<script>` tags including import maps |
| No integrity verification | 🟡 High | Use `integrity` field in import maps |
| Multiple import maps conflict | 🟡 High | Ensure only one import map, injected early in `<head>` |
| Internal module name exposure | 🟢 Medium | Use hashed/minified paths |
| CDN compromise | 🔴 Critical | Always use integrity hashes + SRI |
| Dynamic import map overwrite | 🟡 High | CSP `script-src` limits injection |
| Path traversal in scopes | 🟢 Medium | Avoid `..` traversal in URL validation |

### Production Checklist

```html
<!-- SECURE production import map template -->
<head>
  <!-- CSP must cover import maps -->
  <meta http-equiv="Content-Security-Policy" content="
    script-src 'nonce-${nonce}' 'strict-dynamic';
  ">
  
  <!-- Single import map, injected server-side -->
  <script type="importmap" nonce="${nonce}">
  {
    "imports": {
      "@app/main": "/assets/main-${hash}.js",
      "@app/auth": "/assets/auth-${hash}.js"
    },
    "integrity": {
      "/assets/main-${hash}.js": "sha384-${integrity.main}",
      "/assets/auth-${hash}.js": "sha384-${integrity.auth}"
    }
  }
  </script>
</head>
```

---