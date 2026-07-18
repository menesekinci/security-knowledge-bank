---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
heading: "Attack Vector 6: Service Worker Update Hijacking"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 8/10
---

## Attack Vector 6: Service Worker Update Hijacking

### The Problem

Service Workers update by re-downloading the SW script. If an attacker can intercept this update (via MitM or cache poisoning), they can replace a legitimate SW with a malicious one.

### How Updates Work

```javascript
// Browser checks for SW updates every 24 hours (by default)
// Update check: navigator.serviceWorker.register('/sw.js')
// If the new /sw.js is different, it's installed

// VULNERABLE: No integrity check on update
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
  // If /sw.js is compromised, attacker controls all future requests
}
```

### Secure Pattern with Integrity

```javascript
// SECURE: Verify SW integrity after registration
async function registerSecureSW() {
  // Fetch SW script and compute hash
  const response = await fetch('/sw.js');
  const swContent = await response.clone().text();
  const swHash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(swContent)
  );
  
  const expectedHash = 'KNOWN_GOOD_HASH_BASE64';
  const actualHash = btoa(String.fromCharCode(...new Uint8Array(swHash)));
  
  if (actualHash !== expectedHash) {
    console.error('Service Worker integrity check failed!');
    return;
  }
  
  navigator.serviceWorker.register('/sw.js');
}
```

---