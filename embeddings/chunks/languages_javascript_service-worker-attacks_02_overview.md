---
source: "languages/javascript/service-worker-attacks.md"
title: "Service Worker Hijacking and Attacks"
heading: "Overview"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 2/10
---

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