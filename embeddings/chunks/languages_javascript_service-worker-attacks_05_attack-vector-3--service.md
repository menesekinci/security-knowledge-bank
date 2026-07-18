---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
heading: "Attack Vector 3: Service Worker Cache Poisoning"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 5/10
---

## Attack Vector 3: Service Worker Cache Poisoning

### The Vulnerability

If a SW has an overly permissive cache strategy, an attacker who can make a single malicious request can poison the SW cache permanently.

### Vulnerable Pattern

```javascript
// sw.js — VULNERABLE: Overly permissive cache
self.addEventListener('fetch', (event) => {
  // Cache-first with no validation
  event.respondWith(
    caches.match(event.request)
      .then(cached => cached || fetch(event.request))
  );
});

// INSTALL: Pre-cache critical resources
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('v1').then(cache => {
      return cache.addAll([
        '/',
        '/js/app.js',
        '/js/vendor.js'
      ]);
    })
  );
});
```

### Exploitation

1. Attacker executes a single XSS or MitM attack
2. Modifies the SW's cache to include malicious resources
3. Cache persists even after the original vulnerability is fixed
4. All users who visited during the window of compromise now have corrupted caches

### Secure Pattern

```javascript
// sw.js — SECURE: Validate cache integrity
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Only cache responses with valid integrity
        if (response.ok && event.request.method === 'GET') {
          const cloned = response.clone();
          caches.open('v2').then(cache => {
            // Validate response content hash
            validateIntegrity(cloned).then(valid => {
              if (valid) cache.put(event.request, cloned);
            });
          });
        }
        return response;
      })
      .catch(() => {
        // Fall back to cache if network fails
        return caches.match(event.request);
      })
  );
});

async function validateIntegrity(response) {
  const body = await response.text();
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  // Compare against expected hash
  return true; // In production, check against known good hashes
}
```

---