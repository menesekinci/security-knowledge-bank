---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Network Security"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 5/11
---

## Network Security

- [ ] **🔴 Enforce HTTPS — block cleartext traffic**
  - Android: `android:usesCleartextTraffic="false"` in manifest
  - iOS: `NSAllowsArbitraryLoads = false` in `Info.plist`
  - Configure `network_security_config.xml` (Android) for per-domain exceptions if needed

- [ ] **🟠 Implement certificate pinning for critical endpoints**
  - Use `http_certificate_pinning` package or native platform pinning
  - Maintain at least one backup pin per host
  - Test pin failure behavior under MiTM conditions (Charles, mitmproxy, Burp Suite)

- [ ] **🟡 Set reasonable timeouts and retry with jitter**
  ```dart
  http.Client().send(http.Request('GET', uri))
      .timeout(const Duration(seconds: 30));
  ```

- [ ] **🟠 Use HSTS on backend and validate `Secure` + `HttpOnly` + `SameSite` cookies**

---