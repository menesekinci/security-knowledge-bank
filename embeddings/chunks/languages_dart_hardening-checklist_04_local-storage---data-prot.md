---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Local Storage & Data Protection"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 4/11
---

## Local Storage & Data Protection

- [ ] **🔴 No sensitive data in `SharedPreferences` / `NSUserDefaults`**
  - Use `flutter_secure_storage` for tokens
  - Use encrypted SQLite (`sqflite` with `sqflite_common_ffi` + encryption) or `sembast` with encryption
  - Consider `drift` (formerly moor) with SQLCipher for local databases

- [ ] **🟡 Wipe all local data on logout**
  ```dart
  await secureStorage.deleteAll();
  await database.close();
  await database.delete();
  // Clear WebView cache and cookies
  await WebViewController().clearCache();
  ```

- [ ] **🔵 Mask sensitive screens in app switcher**
  - Android: `FLAG_SECURE` on Window (blocks screenshots + task switcher)
  - iOS: Snapshot masking (UIApplicationProtectedDataWillBecomeUnavailable)

- [ ] **🟠 Disable backup for sensitive data**
  - Android: `android:allowBackup="false"` in manifest
  - iOS: Exclude sensitive files from iCloud backup with `addSkipBackupAttributeToItemAtURL`

---