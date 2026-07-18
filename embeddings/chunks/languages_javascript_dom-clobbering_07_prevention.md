---
source: "languages/javascript/dom-clobbering.md"
title: "DOM Clobbering Attacks in Modern Frameworks"
heading: "Prevention"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [clobbering, cve-2024-38354, cve-2024-45812, cve-2024-47068, hackmd, javascript, language-vuln, overview, rollup, vite]
chunk: 7/9
---

## Prevention

### Defense 1: Explicit Property Checks

```javascript
// VULNERABLE
if (window.someConfig) {
  init(window.someConfig);
}

// SECURE: Use hasOwnProperty to avoid clobbered properties
if (Object.prototype.hasOwnProperty.call(window, 'someConfig')) {
  init(window.someConfig);
}

// OR use undefined comparison
if (window.someConfig !== undefined) {
  // Still slightly vulnerable—can be clobbered to undefined
}
```

### Defense 2: Use Strict Local Variables

```javascript
// VULNERABLE: Implicit global access
function getConfig() {
  return config;  // Could resolve to window.config
}

// SECURE: Always use explicit local declarations
function getConfig() {
  const localConfig = { apiBase: '/api/' };
  return localConfig;
}
```

### Defense 3: Content Security Policy

```html
<!-- CSP can partially mitigate DOM Clobbering -->
<meta http-equiv="Content-Security-Policy" content="
  script-src 'self' 'nonce-abc123';
  base-uri 'self';
  require-trusted-types-for 'script';
">
```

### Defense 4: Framework-Specific Protections

```typescript
// Angular: DomSanitizer properly handles DOM access
import { DomSanitizer } from '@angular/platform-browser';

// React: JSX doesn't use named DOM access for global resolution

// Svelte: Compiled templates avoid runtime DOM lookups

// Vue: $el and template refs are controlled
```

### Defense 5: Build Tool Hardening

```javascript
// vite.config.js — SECURE configuration
export default {
  build: {
    // Use ESM format (not vulnerable to DOM Clobbering)
    rollupOptions: {
      output: {
        format: 'es'  // NOT 'iife', 'cjs', or 'umd'
      }
    }
  },
  // Upgrade to latest versions
}
```

---