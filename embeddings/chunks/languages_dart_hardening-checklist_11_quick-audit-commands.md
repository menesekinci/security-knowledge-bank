---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Quick Audit Commands"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 11/11
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