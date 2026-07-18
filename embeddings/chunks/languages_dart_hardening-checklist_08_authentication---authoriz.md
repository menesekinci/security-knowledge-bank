---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Authentication & Authorization"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 8/11
---

## Authentication & Authorization

- [ ] **🟠 Use OAuth2/OIDC with PKCE — never embed client secrets in app binary**
  - Use `appauth` or `firebase_auth` with secure token storage via `flutter_secure_storage`

- [ ] **🔴 Always enforce authorization server-side, never in Dart/UI alone**
  - Client-side auth checks are trivially bypassable with Frida or binary manipulation

- [ ] **🟡 Implement biometric gating for high-value actions**
  ```dart
  final auth = LocalAuthentication();
  final didAuth = await auth.authenticate(
    localizedReason: 'Confirm your identity to view payment info',
  );
  ```

- [ ] **🟡 Implement token refresh rotation and proper session invalidation**

---