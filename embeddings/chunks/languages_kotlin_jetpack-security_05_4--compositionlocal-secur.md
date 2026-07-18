---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "4. CompositionLocal Security"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 5/8
---

## 4. CompositionLocal Security

### The CompositionLocal Attack Surface

```kotlin
// VULNERABLE: Exposing sensitive services via CompositionLocal
val LocalAuthService = staticCompositionLocalOf<AuthService> { 
    error("No AuthService provided") 
}

// Any composable anywhere in the tree can inject a fake AuthService
@Composable
fun RootApp() {
    CompositionLocalProvider(LocalAuthService provides FakeAuthService()) {
        // All children now use the fake auth service!
        // An attacker's composable can do this:
        MyApp()
    }
}

// Malicious composable:
@Composable
fun MaliciousOverlay() {
    val authService = LocalAuthService.current
    
    // Bypass all auth checks
    CompositionLocalProvider(LocalAuthService provides AdminBypassService()) {
        AdminPanel()
    }
}

// SECURE: Use read-only interfaces
interface AuthChecker {
    val isAuthenticated: Boolean
    fun hasRole(role: String): Boolean
}

// Implementation with write methods is separate
class AuthService : AuthChecker {
    override val isAuthenticated: Boolean
        get() = _isAuthenticated.value
    
    private val _isAuthenticated = MutableStateFlow(false)
    
    fun login(token: String) { /* ... */ }
}

// Only expose the interface via CompositionLocal
val LocalAuthChecker = staticCompositionLocalOf<AuthChecker> { 
    error("No AuthChecker provided")
}
```

### CompositionLocal Scope — Keep It Tight

```kotlin
// VULNERABLE: CompositionLocal provided too broadly
@Composable
fun App() {
    CompositionLocalProvider(LocalUserData provides viewModel.userData) {
        // User data available to EVERY composable in the app
        // Including third-party library composables!
        Navigation()
    }
}

// SECURE: Provide only where needed
@Composable
fun App() {
    Navigation()
}

@Composable
fun UserProfileSection(userData: UserData) {
    CompositionLocalProvider(LocalUserData provides userData) {
        // Only children of UserProfileSection have access
        UserDetailsCard()
        UserPreferencesEditor()
    }
}
```

---