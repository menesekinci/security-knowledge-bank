---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "2. NavigationLink & Deep Link Security"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 3/9
---

## 2. NavigationLink & Deep Link Security

### NavigationLink Exploitation

```swift
// VULNERABLE: NavigationLink with user-controllable destination
struct ContentView: View {
    var body: some View {
        NavigationStack {
            List(articles) { article in
                NavigationLink(article.title, 
                    destination: ArticleDetailView(articleID: article.id))
            }
            // ⚠️ If article.id is user-controllable, any article is accessible!
        }
    }
}

struct ArticleDetailView: View {
    let articleID: String
    
    var body: some View {
        // Fetches and displays article — no authorization check!
        Text(fetchArticle(id: articleID))
    }
}

// SECURE: Authorize access in destination
struct SecureArticleDetailView: View {
    let articleID: String
    @EnvironmentObject var authService: AuthService
    
    var body: some View {
        Group {
            if authService.canAccessArticle(articleID) {
                ArticleContent(id: articleID)
            } else {
                AccessDeniedView()
            }
        }
    }
}
```

### Deep Link Hijacking — Universal Links Security

```xml
<!-- VULNERABLE Info.plist: Accepting arbitrary deep links -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <!-- Any app can register "myapp://" scheme -->
        </array>
    </dict>
</array>
```

```swift
// VULNERABLE: No validation on incoming deep link
@main
struct MyApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL { url in
                    // ⚠️ Directly navigates based on URL — NO VALIDATION
                    handleDeepLink(url)
                }
        }
    }
    
    func handleDeepLink(_ url: URL) {
        // https://myapp.com/profile/123
        let path = url.pathComponents  // ["/", "profile", "123"]
        if path[1] == "profile" {
            navigateToProfile(userID: path[2])  // No ownership check!
        }
    }
}

// SECURE: Validate and authorize deep links
func handleDeepLink(_ url: URL) {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let host = components.host else {
        return
    }
    
    // Verify the URL is from your domain (Universal Link)
    guard host == "myapp.com" else {
        return  // Ignore custom URL scheme links from unknown sources
    }
    
    // host is already validated as "myapp.com" by the guard above.
    // pathComponents looks like ["/", "profile", "123"] — Swift can't match
    // array literals in a `case`, so match on count + elements with `where`.
    let path = url.pathComponents
    
    switch path {
    case let p where p.count == 3 && p[1] == "profile":
        let userID = p[2]
        // Only navigate if the authenticated user owns this profile
        guard authService.currentUser?.id == userID else {
            showAccessDenied()
            return
        }
        navigateToProfile(userID: userID)
    case let p where p.count == 2 && p[1] == "settings":
        navigateToSettings()
    default:
        break
    }
}
```

### Universal Link Hijacking Case Study (Temu — 2024)

In 2024, Temu's iOS app misconfigured their `apple-app-site-association` (AASA) file, allowing **Universal Link Hijacking**:

- The AASA file had overly broad path matching
- Any app on the device could claim the same universal link patterns
- Malicious apps could intercept Temu's deep links for phishing

**The Vulnerability:**
```json
// VULNERABLE AASA file — too permissive
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.temu",
      "paths": ["*"]  // ⚠️ ALL paths match!
    }]
  }
}
```

**Secure AASA:**
```json
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.temu",
      "paths": ["/product/*", "/search/*", "/account/*"]
    }]
  }
}
```

**References:**
- [Universal Link Hijacking via Misconfigured AASA on Temu.com](https://medium.com/@m.habibgpi/universal-link-hijacking-via-misconfigured-aasa-file-on-temu-com-eadfcb745e4e)
- [Hijacking iOS Deep Links via Custom URL Schemes](https://blog.dixitaditya.com/hijacking-ios-deep-links-in-a-health-app-using-custom-url-schemes)

---