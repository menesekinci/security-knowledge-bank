# 🟠 Swift Deep Link Hijacking

## What Is It?
**Phishing** and **session hijacking** resulting from AI missing validation when deep linking with `universal link` or `custom URL scheme` on iOS.

## Example
```swift
// 💀 VULNERABLE:
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let token = url.queryParameters?["token"]
    UserDefaults.standard.set(token, forKey: "auth_token")
    // Any app can call this URL scheme!
    // myapp://login?token=FAKE_TOKEN → session hijack 💀
}

// ✅ SAFE:
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // 1. Source app check:
    guard options[.sourceApplication] as? String == "com.trusted.app" else {
        return false
    }
    // 2. Universal link validation:
    guard url.host == "api.myapp.com" else {
        return false
    }
    // 3. Token validation:
    guard let token = url.queryParameters?["token"],
          validateTokenOnServer(token) else {
        return false
    }
    KeychainWrapper.standard.set(token, forKey: "auth_token")
    return true
}
```

## Prevention Methods
- Use **Universal Link** instead of custom URL scheme
- Verify the apple-app-site-association file for universal links
- Validate received tokens on the server
- Check the source app

---

**Severity: 🟠 High** — Phishing, session hijack.
