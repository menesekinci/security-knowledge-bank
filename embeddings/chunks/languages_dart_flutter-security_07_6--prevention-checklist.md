---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "6. Prevention Checklist"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 7/9
---

## 6. Prevention Checklist

1. **Never hardcode secrets in Dart code** — Use `flutter_dotenv` for build-time values, a backend proxy for runtime secrets
2. **Use `flutter_secure_storage` for tokens** — Backed by Android Keystore / iOS Keychain
3. **Enable Flutter obfuscation** — `flutter build apk --obfuscate --split-debug-info=build/symbols`
4. **Validate all WebView inputs** — URL allowlist, `JavaScriptMode.disabled` unless necessary, sanitize JS channel messages
5. **Prefer Android App Links / iOS Universal Links** — Avoid custom URL schemes for deep linking
6. **Implement certificate pinning** — Use `http_certificate_pinning` or similar for critical API endpoints
7. **Audit `pubspec.yaml` dependencies** — Check for known CVEs with `dart pub outdated` and `flutter pub audit`
8. **Remove debug logging in release** — Guard `print()` / `debugPrint()` behind `kReleaseMode` or use a logger that strips in production
9. **Set `FLAG_SECURE` on Android** — Prevent screenshots of sensitive screens (Android `WindowManager`)
10. **Use `android:allowBackup="false"`** — Prevent ADB backup data exfiltration
11. **Set `android:usesCleartextTraffic="false"`** — Block HTTP in production
12. **Keep Flutter SDK and all packages updated** — Subscribe to [flutter-announce](https://groups.google.com/g/flutter-announce)
13. **Implement biometric gating** — Use `local_auth` package for sensitive operations
14. **Run `dart analyze` with strict mode** — Enable all lint rules that catch security issues
15. **Validate platform channel inputs** — Treat all data from platform channels as untrusted
16. **Don't ship debug symbols** — Store `build/symbols` and `build/app/outputs/mapping` server-side only

---