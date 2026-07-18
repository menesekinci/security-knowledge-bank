---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "3. Data Injection & State Manipulation"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 4/9
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