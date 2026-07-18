---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Deep Linking & Inter-App Communication"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 7/11
---

## Deep Linking & Inter-App Communication

- [ ] **🔴 Prefer Android App Links / iOS Universal Links over custom URL schemes**
  - Custom URL schemes can be hijacked by any app that registers the same scheme
  - App Links/Universal Links verify domain ownership via digital asset links

- [ ] **🟠 Validate deep link origins and paths — reject unknown hosts and schemes**
  ```dart
  if (uri.scheme != 'https') return;
  if (!allowedHosts.contains(uri.host)) return;
  if (!allowedPaths.contains(uri.path)) return;
  ```

- [ ] **🟡 Add `android:autoVerify="true"` for App Links to enforce domain verification**
- [ ] **🟡 Don't export unnecessary activities** — Set `android:exported="false"` on activities that don't need external launch

---