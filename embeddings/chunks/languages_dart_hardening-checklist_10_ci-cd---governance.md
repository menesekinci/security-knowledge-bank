---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "CI/CD & Governance"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 10/11
---

## CI/CD & Governance

- [ ] **🟠 Run `dart analyze` with strict lint rules enabled**
  ```yaml
  # analysis_options.yaml
  analyzer:
    errors:
      unused_import: error
      unnecessary_cast: error
  linter:
    rules:
      - always_declare_return_types
      - avoid_print
      - prefer_const_constructors
      - prefer_final_locals
  ```

- [ ] **🟠 Gate releases on SAST + SCA scan results — block on High/Critical findings**
- [ ] **🟡 Generate and archive SBOM with every release** (pubspec.lock + Gradle/CocoaPods manifests)

- [ ] **🟡 Subscribe to security announcements**
  - [flutter-announce](https://groups.google.com/g/flutter-announce)
  - [Dart SDK security advisories](https://github.com/dart-lang/sdk/security)
  - [Flutter security advisories](https://github.com/flutter/flutter/security)

---