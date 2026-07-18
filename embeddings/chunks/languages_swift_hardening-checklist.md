---
source: "languages/swift/hardening-checklist.md"
title: "🍎 Swift / iOS Security Hardening Checklist"
category: "checklist"
language: "swift"
severity: "medium"
tags: [authentication, checklist, code, coding, data, network, storage, swift, vibe]
---

# 🍎 Swift / iOS Security Hardening Checklist

> Items to verify in every iOS project before deployment.

## ✅ Data Storage
- [ ] Is sensitive data in the Keychain? (not UserDefaults)
- [ ] Is the Keychain access level correct? (ThisDeviceOnly)
- [ ] Is Core Data / SQLite encrypted?
- [ ] Is there no sensitive data in `NSUserDefaults`?

## ✅ Network
- [ ] Is ATS (App Transport Security) disabled? (exception domain whitelist)
- [ ] Is certificate pinning implemented?
- [ ] Is HTTPS enforced?
- [ ] Is the WKWebView configuration secure? (JS bridge)

## ✅ Authentication
- [ ] Is biometric (FaceID/TouchID) used correctly?
- [ ] Is the token stored in the Keychain rotated?
- [ ] Is deep link validation performed?
- [ ] Was the Universal link apple-app-site-association verified?

## ✅ Code
- [ ] Is there no `!` force unwrap? (Is optional binding used?)
- [ ] Is `try!` avoided? (Is do-catch used?)
- [ ] Is Codable deserialization secure?
- [ ] Is the JavaScriptCore bridge security-controlled?

## 🛡️ Vibe Coding Extra
- [ ] Was the AI's `UserDefaults` suggestion rejected? (use Keychain)
- [ ] Was the AI's force unwrap (`!`) usage replaced with optional binding?
- [ ] Was the AI's deep link validation verified?
