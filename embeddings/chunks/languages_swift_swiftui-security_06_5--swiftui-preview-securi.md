---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "5. SwiftUI Preview Security"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 6/9
---

## 5. SwiftUI Preview Security

```swift
// VULNERABLE: Preview uses real data/services
struct ProfileView_Previews: PreviewProvider {
    static var previews: some View {
        ProfileView()
            .environmentObject(RealAuthService())  // Real API calls!
    }
}

// SECURE: Use mock data in previews
struct ProfileView_Previews: PreviewProvider {
    static var previews: some View {
        ProfileView()
            .environmentObject(MockAuthService())  // Mock data only
    }
}

// SECURE: Never include real credentials in preview providers
// ⚠️ AI-generated code often includes real-looking data in previews
struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView()
            .environmentObject(
                AuthService(apiKey: "sk-real-key-here")  // NEVER do this!
            )
    }
}
```

---