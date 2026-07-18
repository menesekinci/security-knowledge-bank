---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
heading: "Attack Vector 5: PostMessage to Service Worker"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 7/10
---

## Attack Vector 5: PostMessage to Service Worker

### The Problem

Service Workers can receive messages via `postMessage()`. If the SW doesn't validate the message source, an attacker can inject commands.

### Vulnerable Pattern

```javascript
// main.js — Sends commands to SW
navigator.serviceWorker.controller.postMessage({
  type: 'CACHE_URL',
  url: userControlledUrl  // Attacker controls this!
});

// sw.js — VULNERABLE: No origin validation
self.addEventListener('message', (event) => {
  if (event.data.type === 'CACHE_URL') {
    // Caches attacker-controlled URL — potential cache poisoning
    caches.open('dynamic').then(cache => {
      cache.add(event.data.url);  // Attacker controls URL!
    });
  }
});
```

### Secure Pattern

```javascript
// sw.js — SECURE: Validate message origins
const ALLOWED_ORIGINS = ['https://example.com'];

self.addEventListener('message', (event) => {
  // Validate message source
  if (!ALLOWED_ORIGINS.includes(event.origin)) {
    return;  // Reject messages from unknown origins
  }
  
  // Validate message structure
  if (!event.data || typeof event.data !== 'object') return;
  
  if (event.data.type === 'CACHE_URL') {
    const url = new URL(event.data.url, self.location.origin);
    
    // Only allow caching same-origin URLs
    if (url.origin !== self.location.origin) return;
    
    caches.open('dynamic').then(cache => {
      cache.add(url.href);
    });
  }
});
```

---