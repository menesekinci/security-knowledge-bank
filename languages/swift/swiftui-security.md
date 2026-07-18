# 🍎 SwiftUI Security Guide

> **Category:** Languages / Swift / SwiftUI
> **Last Updated:** July 2026
> **Description:** SwiftUI-specific security concerns — data flow security, @State/@StateObject misuse, NavigationLink deep link hijacking, and common vulnerability patterns in SwiftUI apps.

---

## 1. SwiftUI Data Flow Security

### Property Wrapper Danger Zones

SwiftUI's property wrappers control data flow, but improper use can lead to data leaks and unauthorized state manipulation:

```
┌──────────────────────────────────────────────────┐
│            SWIFTUI PROPERTY WRAPPERS              │
├──────────────┬────────────────┬──────────────────┤
│   Wrapper    │   Scope        │   Security Risk   │
├──────────────┼────────────────┼──────────────────┤
│ @State       │ Local view     │ Data injection    │
│ @StateObject │ View owns      │ Lifetime issues   │
│ @ObservedObject│ View observes│ Data exposure     │
│ @Environment  │ Global tree   │ Theft via modifier│
│ @AppStorage   │ UserDefaults  │ PII leak          │
│ @Binding      │ Two-way       │ Unintended mutate │
│ @FetchRequest │ CoreData      │ Predicate injection│
└──────────────┴────────────────┴──────────────────┘
```

### @State Security

```swift
// VULNERABLE: @State holds sensitive data
struct LoginView: View {
    @State private var password: String = ""  // Can be read by memory debugger
    @State private var isAuthenticated: Bool = false
    
    var body: some View {
        VStack {
            SecureField("Password", text: $password)
            Button("Login") { authenticate() }
        }
    }
}

// SECURE: Don't store secrets in @State — use Keychain
struct LoginView: View {
    @State private var password: String = ""
    @StateObject private var authManager = AuthManager()
    
    var body: some View {
        VStack {
            SecureField("Password", text: $password)
            Button("Login") {
                Task { await authManager.authenticate(password: password) }
                password = ""  // Clear immediately
            }
        }
    }
}

class AuthManager: ObservableObject {
    @Published var isAuthenticated = false
    
    func authenticate(password: String) async {
        // Call backend — never store password locally beyond this function
        let result = try? await APIClient.login(password: password)
        await MainActor.run {
            isAuthenticated = result != nil
        }
    }
}
```

### @StateObject vs @ObservedObject — Security Implications

```swift
// VULNERABLE: @ObservedObject in a child view can be recreated
struct ParentView: View {
    @State private var count = 0
    
    var body: some View {
        ChildView(viewModel: ViewModel())
        // ⚠️ ViewModel is recreated on each parent render!
        // If ViewModel has auth state, it gets reset!
    }
}

struct ChildView: View {
    @ObservedObject var viewModel: ViewModel
    
    var body: some View {
        Text("\(viewModel.data)")
    }
}

// SECURE: @StateObject ensures stable lifetime
struct SecureParentView: View {
    @StateObject private var viewModel = ViewModel()
    
    var body: some View {
        ChildView(viewModel: viewModel)
        // ViewModel persists across parent re-renders
    }
}
```

### @Environment Data Injection

```swift
// VULNERABLE: Overly permissive environment injection
struct UserProfileKey: EnvironmentKey {
    static let defaultValue = UserProfile()  // Default = empty profile
}

extension EnvironmentValues {
    var userProfile: UserProfile {
        get { self[UserProfileKey.self] }
        set { self[UserProfileKey.self] = newValue }
    }
}

// Any view can now inject a fake user profile!
SomeView().environment(\.userProfile, fakeAdminProfile)

// SECURE: Restrict environment modification
// Use @Environment(\.managedObjectContext) only with proper auth
// Don't inject sensitive user data via environment — use a service

// SECURE: Use a dedicated auth service instead
class AuthService: ObservableObject {
    @Published var currentUser: User?
    
    func hasPermission(_ permission: Permission) -> Bool {
        currentUser?.role.permissions.contains(permission) ?? false
    }
}

struct ContentView: View {
    @EnvironmentObject var authService: AuthService
    // Only one true source of auth state
}
```

### @AppStorage — UserDefaults Security

```swift
// VULNERABLE: Storing sensitive data in @AppStorage
struct SettingsView: View {
    @AppStorage("auth_token") private var authToken: String = ""
    @AppStorage("user_email") private var userEmail: String = ""
    
    // Auth token and email stored in plaintext UserDefaults!
    // Accessible via: defaults read com.yourapp.plist
}

// SECURE: Use Keychain for sensitive data
@propertyWrapper
struct KeychainStorage: DynamicProperty {
    let key: String
    @State private var value: String = ""
    
    var wrappedValue: String {
        get { KeychainHelper.read(key: key) ?? "" }
        nonmutating set {
            KeychainHelper.save(key: key, value: newValue)
            _value = State(initialValue: newValue)
        }
    }
}

struct SecureSettingsView: View {
    @KeychainStorage("auth_token") private var authToken: String
    @AppStorage("theme_preference") private var theme: String = "light"
    // Auth token in Keychain, non-sensitive pref in UserDefaults
}
```

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

## 3. Data Injection & State Manipulation

### ObservableObject Injection

```swift
// VULNERABLE: View exposes its ViewModel to environment
struct ContentView: View {
    @StateObject private var viewModel = ProfileViewModel()
    
    var body: some View {
        ProfileView()
            .environmentObject(viewModel)  // Any child can modify this!
    }
}

// Malicious child view could inject:
struct MaliciousChildView: View {
    @EnvironmentObject var viewModel: ProfileViewModel
    
    var body: some View {
        Text("")
            .onAppear {
                viewModel.isAdmin = true  // Privilege escalation!
            }
    }
}

// SECURE: Use protocols to limit exposure
protocol ProfileViewModelProtocol: AnyObject {
    var displayName: String { get }
    var profileImage: URL? { get }
    func refresh() async
    // Don't expose setters for sensitive properties
}

class ProfileViewModel: ProfileViewModelProtocol, ObservableObject {
    @Published private(set) var displayName: String
    @Published private(set) var profileImage: URL?
    @Published private(set) var isAdmin: Bool = false  // Private setter!
}
```

### Sheet/Presentation Data Injection

```swift
// `.sheet(item:)` requires an Identifiable item — a bare String? won't compile.
// Wrap the id in a small Identifiable struct.
struct SelectedUser: Identifiable {
    let id: String
}

// VULNERABLE: Sheet with user-controllable data
struct ContentView: View {
    @State private var selectedUser: SelectedUser?
    
    var body: some View {
        List(users) { user in
            Button(user.name) {
                selectedUser = SelectedUser(id: user.id)
            }
        }
        .sheet(item: $selectedUser) { selection in
            // ⚠️ If user.id is manipulated, any user profile shows
            UserProfileView(userID: selection.id)
        }
    }
}

// SECURE: Authorize before presenting
.sheet(item: $selectedUser) { selection in
    if authService.canViewProfile(selection.id) {
        UserProfileView(userID: selection.id)
    } else {
        EmptyView()
    }
}
```

---

## 4. ATS (App Transport Security)

```xml
<!-- VULNERABLE: Complete ATS disable — DeepSeek case (Feb 2025) -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- ALLOWED: all HTTP traffic in cleartext! -->
</dict>

<!-- SECURE: Allow specific domains only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.myapp.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSIncludesSubdomains</key>
            <false/>
        </dict>
    </dict>
</dict>

<!-- BEST: Use certificate pinning -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.myapp.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedLeafIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-Base64</key>
                    <string>base64EncodedPublicKeyHash==</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

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

## 6. Background Task Security

```swift
// VULNERABLE: BGTaskScheduler without authentication check
func registerBackgroundTask() {
    BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.app.refresh", using: nil) { task in
        handleBackgroundRefresh(task: task as! BGAppRefreshTask)
    }
}

func handleBackgroundRefresh(task: BGAppRefreshTask) {
    // ⚠️ No auth check — runs with whatever credentials were last stored
    fetchSensitiveUserData()
}

// SECURE: Verify session validity before background work
func handleBackgroundRefresh(task: BGAppRefreshTask) {
    task.expirationHandler = { task.setTaskCompleted(success: false) }
    
    Task {
        guard await authService.hasValidSession() else {
            task.setTaskCompleted(success: false)
            return
        }
        await fetchSensitiveUserData()
        task.setTaskCompleted(success: true)
    }
}
```

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

## References

- [Apple — Securing Data in the UI Layer](https://developer.apple.com/documentation/security/securing_data_in_the_ui_layer)
- [Apple — Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections)
- [OWASP iOS Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Hijacking iOS Deep Links via Custom URL Schemes](https://blog.dixitaditya.com/hijacking-ios-deep-links-in-a-health-app-using-custom-url-schemes)
- [DeepSeek iOS ATS Disabled (Feb 2025)](https://hawk-eye.io/2025/02/weekly-threat-landscape-digest-week-6/)
- [Universal Link Hijacking — Temu](https://medium.com/@m.habibgpi/universal-link-hijacking-via-misconfigured-aasa-file-on-temu-com-eadfcb745e4e)
- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web)
