---
source: "languages/javascript/css-injection.md"
title: "CSS Injection and Data Exfiltration"
category: "language-vuln"
language: "javascript"
chunk: 7
total_chunks: 8
heading: "Prevention"
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