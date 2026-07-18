---
source: "languages/javascript/timing-attacks-js.md"
title: "Timing Attack Vectors in JavaScript/TypeScript"
heading: "Node.js crypto.timingSafeEqual Limitations"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [considerations, cve-2023-46809, cve-2026-21713, general, javascript, language-vuln, node, overview, timing, typescript-specific]
chunk: 7/8
---

## Node.js crypto.timingSafeEqual Limitations

```javascript
const crypto = require('crypto');

// LIMITATION 1: Buffer length must match
// If they differ, timingSafeEqual throws — this is a timing oracle!
try {
  crypto.timingSafeEqual(
    Buffer.from('short'),
    Buffer.from('very long secret')
  );
} catch (err) {
  // Exception thrown — attacker knows lengths differ!
}

// WORKAROUND: Pad to consistent length
function safeCompare(input, secret) {
  const maxLen = Math.max(input.length, secret.length);
  const inputPadded = Buffer.alloc(maxLen, input, 'utf-8');
  const secretPadded = Buffer.alloc(maxLen, secret, 'utf-8');
  return crypto.timingSafeEqual(inputPadded, secretPadded);
}

// LIMITATION 2: Not available in all environments
// Browser crypto.subtle doesn't have timingSafeEqual
// For browsers, use Double HMAC strategy:
async function browserSafeCompare(input, secret) {
  const encoder = new TextEncoder();
  const key1 = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  
  const inputHmac = await crypto.subtle.sign(
    'HMAC', key1, encoder.encode(input)
  );
  const secretHmac = await crypto.subtle.sign(
    'HMAC', key1, encoder.encode(secret)
  );
  
  // Compare HMACs — the HMAC is what leaks, not the secret itself
  return crypto.subtle.timingSafeEqual(inputHmac, secretHmac);
}
```

---