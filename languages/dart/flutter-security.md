# 🔴 Flutter Security

> Comprehensive guide to Flutter / Dart security vulnerabilities, with focus on AI-generated and vibe-coded mobile applications.

- **Severity:** High
- **CWEs:** CWE-312 (Cleartext Storage), CWE-276 (Incorrect Default Permissions), CWE-200 (Info Exposure), CWE-287 (Improper Auth), CWE-94 (Code Injection), CWE-798 (Use of Hardcoded Credentials), CWE-862 (Missing Authorization), CWE-22 (Path Traversal)
- **AI Generation Risk:** High

---

## 1. Vulnerability Explanation — Flutter/Dart Specific Risks

### 1.1 Hardcoded API Keys and Secrets in Dart Code

Flutter apps frequently embed API keys, Firebase configs, and secrets directly in Dart source files as string literals. Unlike web apps where secrets can be server-side, Flutter apps compile all Dart code into a single `libapp.so` (Android) or the app binary (iOS). **Any string literal in Dart code is trivially recoverable** via `strings` on Linux/macOS or a hex editor on the compiled binary.

```dart
// VULNERABLE: Recoverable via `strings libapp.so`
String apiKey = "AIzaSyD8eN4hQm2xV9K3LpR7tW6yZ5cX4bV3nA2s";
String firebaseProjectId = "my-app-12345";
```

Obfuscation (`--obfuscate`) renames symbols but does **not** encrypt or hide string values. Tools like `strings`, `jadx`, and `ghidra` can extract all constant strings from a release APK/IPA in seconds.

### 1.2 Insecure Local Storage

The default local storage choice for many AI-generated Flutter apps is `SharedPreferences` (via the `shared_preferences` package). On Android, this stores data as **unencrypted XML** in the app's private directory. On rooted devices or via ADB backups, this data is fully readable.

```dart
// VULNERABLE: Tokens stored in plaintext
final prefs = await SharedPreferences.getInstance();
await prefs.setString('auth_token', 'eyJhbGci...');
```

On iOS, `SharedPreferences` backs to `NSUserDefaults`, which is stored as a plaintext plist file — readable on jailbroken devices or via encrypted backups.

**What AI generators often miss**: AI models frequently default to `shared_preferences` because it's the simplest, most documented package. They rarely import `flutter_secure_storage` unless explicitly prompted.

### 1.3 WebView XSS / JavaScript Channel Injection

Flutter's `webview_flutter` package exposes a `JavaScriptChannel` API that allows Dart and JavaScript to communicate. AI-generated apps often:

- Enable JavaScript mode without restriction
- Load arbitrary URLs without validation
- Use `JavaScriptChannel` to pass sensitive data from JS to Dart
- Fail to sanitize the JS bridge messages

```dart
// VULNERABLE: Unrestricted WebView with JS bridge
WebViewController controller = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..addJavaScriptChannel('AppBridge',
      onMessageReceived: (JavaScriptMessage message) {
        // message.message comes from JS — assumed trusted!
        processFromJS(message.message);
      })
  ..loadRequest(Uri.parse('https://example.com'));
```

**The risk**: If an attacker can inject XSS into the loaded page (via a reflected XSS, compromised CDN, or MiTM on HTTP resources), they can call `AppBridge.postMessage()` with arbitrary data, which Dart treats as a trusted call. This can leak tokens, trigger payments, or exfiltrate local data.

### 1.4 Deep Link Hijacking

AI-generated apps often implement deep linking with custom URL schemes (e.g., `myapp://profile/123`) without validating the origin or path. This opens the door to:

- **Custom scheme hijacking** — On Android, any app can register the same scheme
- **Open redirect** — Deep link handler passes URL parameters directly to WebView or navigation
- **Intent injection** — Malicious apps craft intents that match the app's intent filter

```dart
// VULNERABLE: No origin or path validation
onGenerateRoute: (settings) {
  // settings.name could be myapp://evil.com/steal
  final uri = Uri.parse(settings.name ?? '');
  final path = uri.host;  // Attacker-controlled!
  return MaterialPageRoute(
    builder: (_) => ProfileScreen(userId: path),
  );
}
```

### 1.5 Firebase Configuration Exposure

This is the #1 AI-generation mistake. When prompted "Build a Flutter app with Firebase backend", AI models typically:

1. Generate a `google-services.json` (Android) or `GoogleService-Info.plist` (iOS)
2. Place these files in the project root
3. Suggest committing everything to git

These files contain `api_key`, `project_id`, `mobilesdk_app_id`, and `database_url` — all **non-secret but sensitive** identifiers. While Firebase API keys alone don't grant access, they enable abuse of Firebase services (FCM spam, Firestore query brute-forcing, storage bucket enumeration) if security rules are misconfigured — which they almost always are in AI-generated projects.

### 1.6 FlutterShell / Dart VM Injection

Flutter's AOT-compiled Dart code still uses a minimal VM for GC and reflection. Two attack vectors:

1. **FlutterShell backdoors** (Operation FlutterBridge, 2026): macOS malvertising campaign delivered Flutter-based backdoors that passed Apple notarization. The malware used the Flutter framework as a Trojan horse, registering `flutterInvoke` JS message channels for C2 communication.

2. **Dart pub cache symlink attacks** (CVE-2026-27704): The Dart pub package manager was vulnerable to "zip slip" via symlinks — a malicious package could extract files outside the pub cache directory, enabling path traversal and supply chain poisoning.

### 1.7 OWASP Mobile Top 10 Mapping

| OWASP 2024 Risk | Flutter-Specific Manifestation | AI Risk |
|-----------------|-------------------------------|---------|
| M1: Improper Credential Usage | Hardcoded API keys, SharedPreferences for tokens | Very High |
| M2: Inadequate Supply Chain | Untrusted pub packages, no `pubspec.lock` auditing | High |
| M3: Insecure Auth/Authorization | No PKCE, WebView-based login, weak session mgmt | High |
| M4: Insufficient I/O Validation | WebView JS channel without sanitization | High |
| M5: Insecure Communication | No certificate pinning, HTTP fallback | Medium |
| M6: Inadequate Privacy Controls | No FLAG_SECURE, clipboard logging, analytics leaks | Medium |
| M7: Insufficient Binary Protection | No obfuscation, debug symbols shipped | High |
| M8: Security Misconfiguration | `AndroidManifest.xml` exported activities, debug builds | High |
| M9: Insecure Data Storage | SharedPreferences, unencrypted SQLite, no `flutter_secure_storage` | Very High |
| M10: Insufficient Cryptography | Custom AES implementations, weak random, ECB mode | Medium |

---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

AI code generators produce Flutter code that **works functionally but ignores security** because security constraints are rarely specified in prompts.

| Prompt Pattern | Generated Vulnerability |
|---------------|------------------------|
| "Build a Flutter app with Firebase" | `google-services.json` in repo, hardcoded `apiKey`, FCM tokens stored in SharedPreferences |
| "Add Google login" | WebView with JS injection, no PKCE, OAuth client secret in Dart code |
| "Store user data locally" | `SharedPreferences` for everything including auth tokens |
| "Implement deep linking" | Custom URL scheme (`myapp://`), no URL or host validation, open redirect |
| "Add a WebView" | `JavaScriptMode.unrestricted`, no allowlist, JS channel passes raw data |
| "Make HTTP requests to API" | No certificate pinning, `http` instead of `https` in development, debug logging of responses |
| "Add crash reporting" | Sentry/ Firebase Crashlytics logging full request/response bodies including tokens |
| "Build the app quickly" | No obfuscation flag (`--obfuscate` missing), debug build shipped |
| "Use this API" | Hardcoded bearer token or API key as `const String` |
| "Add local database" | `sqflite` without encryption, storing PII in plaintext SQLite |

### Why AI Particularly Struggles with Flutter Security

1. **Flutter is a moving target** — AI training cutoffs may miss recent Flutter security advisories (e.g., CVE-2026-27704 requires Dart 3.11+)
2. **Security packages are lesser-known** — `flutter_secure_storage` is less frequently sampled in training data than `shared_preferences`
3. **Compilation model is opaque to AI** — AIs don't model that `const` strings survive AOT compilation
4. **No secure defaults** — Flutter's APIs default to permissive modes (e.g., `JavaScriptMode.unrestricted`)

---

## 3. Vulnerable Code Examples

### 🔴 Hardcoded API Keys

```dart
class ApiConfig {
  // REVERSIBLE: `strings libapp.so | grep AIza`
  static const String firebaseApiKey = 'AIzaSyD8eN4hQm2xV9K3LpR7tW6yZ5cX4bV3nA2s';
  static const String stripeSecret = 'sk_live_xxxxxxxxxxxxx';
  static const String sentryDsn = 'https://xxxxxxxx@o123456.ingest.sentry.io/123456';
}
```

### 🔴 SharedPreferences Token Storage

```dart
// VULNERABLE: Tokens in plaintext on disk
Future<void> saveToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('access_token', token);  // CWE-312
}

Future<String?> getToken() async {
  final prefs = await SharedPreferences.getInstance();
  return prefs.getString('access_token');  // Returns plaintext
}
```

### 🔴 Unrestricted WebView

```dart
WebViewController controller = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..setNavigationDelegate(NavigationDelegate(
    onNavigationRequest: (request) {
      // ALL URLs allowed — no allowlist!
      return NavigationDecision.navigate;
    },
  ))
  ..addJavaScriptChannel('PaymentBridge',
      onMessageReceived: (JavaScriptMessage msg) {
        // Attacker-controlled input processed as trusted
        processPayment(msg.message);
      });
```

### 🔴 Unsafe Deep Link Handler

```dart
// VULNERABLE: No URL validation
class AppDeepLink {
  static Future<void> handleLink(Uri uri) async {
    // No scheme validation
    final path = uri.pathSegments;
    if (path.isNotEmpty && path.first == 'profile') {
      // Open redirect: uri.host could be attacker-controlled
      Navigator.pushNamed(context, path[1]);  // CWE-601
    }
  }
}
```

### 🔴 No Certificate Pinning

```dart
// VULNERABLE: Accepts any valid certificate
final response = await http.get(
  Uri.parse('https://api.example.com/user/data'),
  headers: {'Authorization': 'Bearer $token'},
);
// No pinning — MiTM with a valid CA cert works
```

---

## 4. Secure Code Fix

### ✅ Secure API Key Handling

```dart
// SECURE: Use flutter_dotenv with .env in .gitignore
// .env file (NOT committed):
//   API_BASE_URL=https://api.example.com
//   SENTRY_DSN=https://xxx@o123456.ingest.sentry.io/123456

// In Dart:
import 'package:flutter_dotenv/flutter_dotenv.dart';

class ApiConfig {
  static String get baseUrl => dotenv.env['API_BASE_URL'] ?? '';
  static String get sentryDsn => dotenv.env['SENTRY_DSN'] ?? '';
}

// For truly secret keys, use a backend proxy — never embed in app
```

**Important**: Environment variables at build time (`--dart-define`) are still recoverable from the binary. They just keep secrets out of the source code repo. For production secrets, use a **backend proxy** or **Firebase Remote Config** with access control.

### ✅ Secure Token Storage

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

final secureStorage = const FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
);

Future<void> saveToken(String token) async {
  await secureStorage.write(key: 'auth_token', value: token);
  // iOS: Uses Keychain (encrypted at rest)
  // Android: Uses EncryptedSharedPreferences (AES-256)
}

Future<String?> getToken() async {
  return await secureStorage.read(key: 'auth_token');
}

// On logout:
Future<void> clearTokens() async {
  await secureStorage.deleteAll();
}
```

### ✅ Secure WebView Configuration

```dart
// SECURE: Restricted WebView with allowlist
WebViewController controller = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)  // Only if required
  ..setNavigationDelegate(NavigationDelegate(
    onNavigationRequest: (request) {
      // Strict URL allowlist
      final allowedHosts = ['app.example.com', 'api.example.com'];
      if (allowedHosts.contains(request.url.host)) {
        return NavigationDecision.navigate;
      }
      // Open external URLs in system browser
      launchUrl(request.url, mode: LaunchMode.externalApplication);
      return NavigationDecision.prevent;
    },
  ))
  // Validate all JS channel messages
  ..addJavaScriptChannel('AppBridge',
      onMessageReceived: (JavaScriptMessage msg) {
    final sanitized = sanitizeMessage(msg.message);
    if (sanitized != null) {
      processFromJS(sanitized);
    }
  });

// Input validation for JS bridge
String? sanitizeMessage(String raw) {
  try {
    final decoded = jsonDecode(raw);
    if (decoded is Map && decoded.containsKey('type')) {
      return jsonEncode(decoded);  // Re-serialize to strip functions
    }
  } catch (_) {
    return null;  // Invalid JSON — reject
  }
  return null;
}
```

### ✅ Secure Deep Link Handling

```dart
// SECURE: Validate origins and paths
class SecureDeepLinkHandler {
  static const allowedSchemes = ['https'];
  static const allowedHosts = ['app.example.com'];
  static const allowedPaths = ['/profile', '/order'];

  static Future<void> handleDeepLink(Uri uri) async {
    // 1. Prefer Universal Links / App Links over custom schemes
    if (uri.scheme == 'https' && allowedHosts.contains(uri.host)) {
      final path = uri.path;
      if (allowedPaths.any((p) => path.startsWith(p))) {
        // Validate all query parameters
        final sanitizedParams = _sanitizeParams(uri.queryParameters);
        await navigateTo(path, sanitizedParams);
        return;
      }
    }
    // Reject unknown links
    throw UnsupportedError('Unknown or malformed deep link');
  }

  static Map<String, String> _sanitizeParams(Map<String, String> params) {
    return params.map((key, value) => MapEntry(
      key,
      value.replaceAll(RegExp(r'[<>\'"]'), ''),  // Strip injection chars
    ));
  }
}
```

### ✅ Certificate Pinning

```dart
// SECURE: Certificate pinning with http_certificate_pinning
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

final secureHttp = HttpCertificatePinning(
  allowedSHAFingerprints: {
    'api.example.com': [
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',  // Primary
      'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',  // Backup
    ],
  },
  timeout: 30,
);

// Use for all sensitive API calls
final response = await secureHttp.get(
  Uri.parse('https://api.example.com/user/data'),
  headers: {'Authorization': 'Bearer $token'},
);
```

---

## 5. Real CVEs / Incidents

### Flutter Package CVEs

| CVE | Package | Type | Severity | Patch | Description |
|-----|---------|------|----------|-------|-------------|
| **CVE-2024-54461** | `file_selector_android` | Path Traversal (CWE-23) | 7.1 High | 0.5.1+12 | Unsanitized filenames from malicious document providers allow path traversal |
| **CVE-2024-54462** | `image_picker_android` | Path Traversal (CWE-23) | 7.1 High | 0.8.12+18 | Unsanitized filenames from malicious document providers allow path traversal |
| **CVE-2026-27704** | `dart pub` | Zip Slip / Path Traversal (CWE-22, CWE-59) | 7.8 High | Dart 3.11.0 / Flutter 3.41.0 | Symlink traversal via malicious pub packages — can write files outside pub cache |
| **CVE-2025-65112** | PubNet (Dart package service) | Auth Bypass (CWE-862) | 9.4 Critical | 1.1.3 | Unauthenticated package upload enabling supply chain attacks |

### Supply Chain Incidents

- **CVE-2025-65112 — PubNet Auth Bypass**: A self-hosted Dart/Flutter package registry allowed unauthenticated users to upload packages via `/api/storage/upload`. Attackers could masquerade as legitimate package authors, enabling identity spoofing, privilege escalation, and supply chain attacks. CVSS 9.4 (Critical).
  - Source: https://nvd.nist.gov/vuln/detail/CVE-2025-65112

- **CVE-2026-27704 — Dart Pub Zip Slip**: The Dart package manager's extraction logic did not normalize symlink paths before writing files. A malicious package could use symlinks to write files outside the pub cache directory, enabling arbitrary code execution during package resolution.
  - Source: https://nvd.nist.gov/vuln/detail/CVE-2026-27704

### FlutterShell / Malware

- **Operation FlutterBridge (2026)**: A macOS malvertising campaign distributing "FlutterShell" — a backdoor built using the Flutter framework that passed Apple notarization. The malware registered `flutterInvoke` JavaScript channels for C2 communication, exploiting WebView to exfiltrate data from infected macOS systems.
  - Source: https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/

### Dependency-Related CVEs

| CVE | Component | Impact | Description |
|-----|-----------|--------|-------------|
| CVE-2023-2136 | Skia (rendering engine) | High (RCE) | Integer overflow in Skia via crafted image — impacts any Flutter app rendering untrusted images |
| CVE-2022-3445 | Skia (rendering engine) | High (RCE) | Heap buffer overflow in Skia — affects Flutter's Impeller/Skia renderer |

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

## 7. Vibe-Coding Red Flags 🔴

Watch for these patterns in AI-generated Flutter code:

1. **`const String apiKey = "..."`** — Trivially extractable from binary
2. **`SharedPreferences` for tokens or credentials** — Default AI choice, always wrong
3. **`JavaScriptMode.unrestricted`** — AI defaults to permissive mode
4. **No custom `NavigationDelegate` on WebView** — AI rarely adds allowlists
5. **Missing `--obfuscate` in build commands** — AI code snippets often omit it
6. **Custom URL schemes for deep links** — AI doesn't understand the hijacking risk
7. **No certificate pinning** — AI rarely includes it unless explicitly prompted
8. **Plain `http.get` / `http.post`** — Without pinning, retry, or timeout configuration
9. **`google-services.json` committed to git** — AI may not add it to `.gitignore`
10. **No logout/wipe logic** — AI builds login flows but forgets secure session cleanup
11. **`print()` or `debugPrint()` in production code** — AI doesn't differentiate debug vs. release
12. **`WillPopScope` without auth check** — Back navigation may bypass security screens
13. **Overly permissive `AndroidManifest.xml`** — Exported activities, debuggable release builds
14. **Plaintext SQLite via `sqflite` for PII** — AI uses `sqflite` over `sembast` or encrypted variants
15. **No `pubspec.lock` committed** — Dependency versions drift silently

---

## Sources

- [Flutter Security Docs](https://docs.flutter.dev/security)
- [Flutter Security False Positives](https://docs.flutter.dev/reference/security-false-positives)
- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [8ksec — Securing Flutter Applications](https://8ksec.io/securing-flutter-applications/)
- [Appknox — Flutter App Security Testing](https://www.appknox.com/blog/flutter-app-security-testing-why-most-tools-fail-what-works)
- [Ostorlab — Flutter App Security Checklist](https://docs.ostorlab.co/security/flutter_app_security_checklist.html)
- [NVD — CVE-2024-54461](https://nvd.nist.gov/vuln/detail/CVE-2024-54461)
- [NVD — CVE-2024-54462](https://nvd.nist.gov/vuln/detail/CVE-2024-54462)
- [NVD — CVE-2026-27704](https://nvd.nist.gov/vuln/detail/CVE-2026-27704)
- [NVD — CVE-2025-65112](https://nvd.nist.gov/vuln/detail/CVE-2025-65112)
- [Unit42 — FlutterShell Backdoor](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)
- [Flutter GitHub Security](https://github.com/flutter/flutter/security)
- [Dart SDK Security Advisories](https://github.com/dart-lang/sdk/security)
