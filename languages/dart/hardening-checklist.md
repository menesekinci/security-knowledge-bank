# 🛡️ Flutter / Dart Hardening Checklist

> Actionable checklist for auditing and hardening Flutter/Dart applications — especially AI-generated code.

**Target:** Flutter 3.x+ / Dart 3.x+  
**Severity Legend:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low

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

## Dependency Supply Chain

- [ ] **🟠 Pin dependency versions and commit `pubspec.lock`**
  - Audit regularly: `dart pub outdated` and `dart pub deps`
  - Check for known vulnerabilities

- [ ] **🟠 Review package permissions and health before adding dependencies**
  - Check `pub.dev` for package health, likes, popularity, and recent updates
  - Prefer packages with 100+ likes, maintained within the last 6 months
  - Avoid packages with excessive native permissions

- [ ] **🔵 Use automated dependency scanning in CI**
  - Integrate Dependabot, Snyk, GitHub Advisory Database, or Socket.dev

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

## Quick Audit Commands

```bash
# Check for hardcoded keys in Dart source
grep -rn "AIzaSy\|sk_live\|pk_live\|apiKey\|secret\|token" lib/

# Check for insecure storage patterns
grep -rn "SharedPreferences" lib/

# Check for unrestricted WebView
grep -rn "JavascriptMode.unrestricted\|JavaScriptMode.unrestricted" lib/

# Check for missing obfuscation in build config
grep -rn "obfuscate" android/app/build.gradle

# Audit outdated dependencies
flutter pub outdated

# Static analysis
flutter analyze

# Check obfuscation in release APK
unzip -l build/app/outputs/flutter-apk/app-release.apk | grep libapp.so
strings build/app/outputs/flutter-apk/app-release.apk | grep -i 'key\|secret\|token\|password'
```

---

**See also:** [Flutter Security Deep Dive](flutter-security.md) for detailed vulnerability explanations, CVE references, and secure code examples.
