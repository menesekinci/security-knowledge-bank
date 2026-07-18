---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
heading: "Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 9/10
---

## Prevention Checklist

| Tactic | Risk | Mitigation |
|--------|------|-----------|
| `importScripts()` with user input | 🔴 Critical | Allowlist URLs, validate input |
| DOM Clobbering → SW chain | 🔴 Critical | Use `hasOwnProperty` checks, not `getElementById` |
| Unvalidated postMessage | 🟡 High | Validate `event.origin` and data structure |
| SW cache poisoning | 🟡 High | Integrity validation in fetch handlers |
| SW update hijacking | 🟡 High | Subresource Integrity for SW scripts |
| Excessive SW scope | 🟢 Medium | `Service-Worker-Allowed` header |
| No SW unregister capability | 🟢 Medium | Provide admin UI for SW management |

### Defensive SW Template

```javascript
// sw.js — DEFENSIVE service worker template
const VALID_ORIGINS = [self.location.origin];
const VALID_SCRIPTS = new Set([
  '/sw/workbox.js',
  '/sw/analytics.js'
]);
const CACHE_NAME = 'static-v1';

// Import only allowlisted scripts
const urlParams = new URLSearchParams(location.search);
const extraScript = urlParams.get('script');
if (extraScript && VALID_SCRIPTS.has(extraScript)) {
  self.importScripts(extraScript);
}

// Validate message origins
self.addEventListener('message', (event) => {
  if (!VALID_ORIGINS.includes(event.origin)) return;
  // Process only known message types
  handleMessage(event);
});

// Secure fetch handler with integrity checks
self.addEventListener('fetch', (event) => {
  event.respondWith(fetchWithIntegrity(event.request));
});

async function fetchWithIntegrity(request) {
  try {
    const response = await fetch(request);
    // Only cache same-origin GET requests
    if (response.ok && request.method === 'GET' && 
        new URL(request.url).origin === self.location.origin) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return caches.match(request);
  }
}
```

---