---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Build & Compilation"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 2/11
---

## Build & Compilation

- [ ] **🔴 Enable obfuscation and split debug info**
  ```bash
  flutter build apk --release --obfuscate --split-debug-info=build/symbols
  flutter build ipa --release --obfuscate --split-debug-info=build/symbols
  ```
  Store `build/symbols` server-side only — never ship with the app.

- [ ] **🔴 Enable R8/ProGuard for Android**
  ```gradle
  // android/app/build.gradle
  release {
      minifyEnabled true
      shrinkResources true
      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
  }
  ```

- [ ] **🔴 Strip debug symbols and remove debug builds**
  - No `flutter run --debug` builds for production
  - Remove `print()` / `debugPrint()` in production code (use `kReleaseMode` guards)
  - CI gate: fail builds on debug logging in non-test code on release branches

- [ ] **🟠 Verify no debug flags in release builds**
  - `android:debuggable="false"` in `AndroidManifest.xml` release config
  - No DEBUG feature flags in production

---