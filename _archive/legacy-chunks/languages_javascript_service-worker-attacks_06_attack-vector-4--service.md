---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 10
heading: "Attack Vector 4: Service Worker Scope Escalation"
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