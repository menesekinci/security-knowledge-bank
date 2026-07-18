---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "7. Vibe-Coding Red Flags 🔴"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 8/9
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