# 🍎 Swift / iOS Security

> Apple platform-specific security pitfalls you may encounter in code produced
> with Vibe Coding while doing iOS/macOS development.

---

## 🎯 Vibe Coding Risks in Swift/iOS

| Risk | Why does the AI do it? | Consequence |
|------|-----------------|-------|
| **Keychain Misuse** | Suggests using simple UserDefaults | Credential leak |
| **Insecure Data Storage** | Uses Core Data/SQLite without encryption | Data leak |
| **Deep Link Hijacking** | Skips Universal link validation | Phishing |
| **Jailbreak Detection** | Produces easily bypassable detections | Bypass |
| **Network Security (ATS)** | Suggests disabling ATS entirely | MITM |
| **Certificate Pinning** | Implements it incorrectly | MITM |
| **WebView XSS** | Leaves the WKWebView configuration incomplete | XSS |
| **Insecure Deep Copy** | Incorrect use of NSCoding/Codable | Info leak |

---

## 📋 Table of Contents

1. [🔴 Keychain & Credential Storage](keychain-storage.md)
2. [🔴 Insecure Data Persistence](keychain-storage.md)
3. [🟠 Deep Link Hijacking](deep-links.md)
4. [🟠 ATS Misconfiguration](ios-security-deep.md)
5. [🟠 WebView Security](ios-security-deep.md)
6. [🟡 Jailbreak Detection Bypass](ios-security-deep.md)
7. [🟡 Certificate Pinning Mistakes](ios-security-deep.md)
8. [🟡 Codable & NSCoding Pitfalls](swiftui-security.md)

---

*Related: OWASP Mobile Top 10, Apple Security Guide*
