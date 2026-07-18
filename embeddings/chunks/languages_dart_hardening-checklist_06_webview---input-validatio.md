---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "WebView & Input Validation"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 6/11
---

## WebView & Input Validation

- [ ] **🔴 Restrict `JavaScriptMode` — disable when not required**
  ```dart
  // Only enable if the page explicitly requires JS
  ..setJavaScriptMode(JavaScriptMode.disabled)
  ```

- [ ] **🔴 Implement URL allowlist in `NavigationDelegate`**
  ```dart
  onNavigationRequest: (request) {
    final allowed = ['app.example.com', 'api.example.com'];
    return allowed.contains(request.url.host)
        ? NavigationDecision.navigate
        : NavigationDecision.prevent;
  }
  ```

- [ ] **🟠 Sanitize all JavaScript channel messages — validate JSON structure before processing**
- [ ] **🟡 Clear WebView cache, cookies, and local storage after sensitive flows (auth, payments)**

---