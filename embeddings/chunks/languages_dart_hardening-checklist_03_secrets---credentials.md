---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Secrets & Credentials"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 3/11
---

## Secrets & Credentials

- [ ] **🔴 No hardcoded API keys, tokens, or secrets in Dart source**
  - Verify with: `strings libapp.so | grep -i 'key\|secret\|token\|password'`
  - Use `--dart-define` for compile-time variables or a backend proxy for runtime secrets

- [ ] **🔴 Use `flutter_secure_storage` for all tokens and secrets**
  - Never `SharedPreferences` for auth tokens, refresh tokens, or API keys
  - Configure Android with `encryptedSharedPreferences: true` for `FlutterSecureStorage`

- [ ] **🟠 `.env` (if used) must be in `.gitignore`**
  ```gitignore
  # .gitignore
  .env
  *.env.local
  ```

- [ ] **🟠 No secrets in `AndroidManifest.xml`, `Info.plist`, or asset files**
  - Firebase configs (`google-services.json`, `GoogleService-Info.plist`) in `.gitignore`, injected via CI

---