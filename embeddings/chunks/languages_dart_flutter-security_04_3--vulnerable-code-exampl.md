---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 4/9
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