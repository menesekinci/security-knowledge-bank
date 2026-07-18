---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "7. SwiftUI Hardening Checklist"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 8/9
---

## 7. SwiftUI Hardening Checklist

- [ ] No sensitive data stored in `@AppStorage` — use Keychain wrapper
- [ ] `@State` cleaned immediately after use for sensitive values
- [ ] Deep links validate user ownership before navigation
- [ ] Environment objects expose minimal interfaces (protocols)
- [ ] ATS is NOT fully disabled — use granular exceptions
- [ ] Universal Links use restricted path patterns in AASA
- [ ] Sheet/Popover destinations authorize before display
- [ ] Background tasks verify session validity
- [ ] Previews use mock data, never real credentials
- [ ] `@StateObject` used instead of `@ObservedObject` for view-owned data
- [ ] `@EnvironmentObject` not used for sensitive auth state without protocol
- [ ] NavigationLink destinations check authorization

---