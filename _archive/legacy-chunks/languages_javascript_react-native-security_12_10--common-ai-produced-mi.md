---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 12
total_chunks: 13
heading: "10. Common AI-Produced Misconfigurations"
---

## 10. Common AI-Produced Misconfigurations

1. **Sensitive data in AsyncStorage** — AI frequently uses AsyncStorage for tokens
2. **WebView without restrictions** — `javaScriptEnabled`, `allowFileAccess` left at defaults
3. **Custom scheme deep linking without validation** — No URL origin verification
4. **`eval()` in Hermes** — Dynamic code execution with user input
5. **No certificate pinning** — API calls without TLS validation
6. **Clipboard exposure** — Auto-copying sensitive text
7. **Hardcoded API keys** — Embedding secrets in JS bundle
8. **Insecure OTA updates** — Code Push without integrity verification
9. **Debug mode in production** — Hermes debugger or dev tools exposed
10. **No biometric authentication** — Sensitive app functions without auth gate

---