---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "2. How AI / Vibe Coding Generates These Vulnerabilities"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 3/9
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