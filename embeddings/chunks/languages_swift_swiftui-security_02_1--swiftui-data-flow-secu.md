---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "1. SwiftUI Data Flow Security"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 2/9
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