---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "4. Secure Code Fix"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 5/9
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