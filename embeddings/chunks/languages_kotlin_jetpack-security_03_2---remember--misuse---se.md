---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "2. `remember` Misuse & Security Implications"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 3/8
---

## 2. `remember` Misuse & Security Implications

### Remember for Sensitive Data

```kotlin
// VULNERABLE: remember stores sensitive data in composition
@Composable
fun LoginScreen() {
    // ⚠️ Password stays in memory as long as composable is alive
    var password by remember { mutableStateOf("") }
    var authToken by remember { mutableStateOf<String?>(null) }
    
    // Token can be accessed from heap dump!
}

// SECURE: Clear sensitive data immediately
@Composable
fun LoginScreen(onLoginSuccess: () -> Unit) {
    var password by remember { mutableStateOf("") }
    
    Button("Login") {
        viewModel.login(password)
        password = ""  // Clear immediately after use
    }
}

// SECURE: Don't store auth tokens in composition state
// Use a ViewModel or secure storage instead
class AuthViewModel : ViewModel() {
    private val _isAuthenticated = MutableStateFlow(false)
    val isAuthenticated: StateFlow<Boolean> = _isAuthenticated.asStateFlow()
    
    fun login(password: String) {
        viewModelScope.launch {
            val token = authRepository.login(password)
            secureStorage.saveToken(token)  // Store in encrypted storage
            _isAuthenticated.value = true
        }
    }
}
```

### remember with Derived State

```kotlin
// VULNERABLE: derivedStateOf with incomplete dependencies
@Composable
fun PermissionGate(permission: String, userRole: String) {
    val hasAccess by remember(userRole) {
        derivedStateOf {
            // ⚠️ permission not in keys — stale state!
            userRole == "admin" || allowedPermissions.contains(permission)
        }
    }
    
    if (hasAccess) {
        RestrictedContent()
    }
}

// SECURE: Include all dependencies in keys
@Composable
fun PermissionGate(permission: String, userRole: String) {
    val hasAccess by remember(userRole, permission) {
        derivedStateOf {
            checkPermission(userRole, permission)
        }
    }
}
```

### rememberSaveable — Persistence Bypass

```kotlin
// VULNERABLE: Sensitive data in savedInstance
@Composable
fun PaymentScreen() {
    var creditCardNumber by rememberSaveable { mutableStateOf("") }
    // ⚠️ Survives process death — saved to Bundle → can be logged!
}

// SECURE: Don't save sensitive data across process death
@Composable
fun PaymentScreen() {
    // Use remember (not rememberSaveable) for sensitive temp data
    var creditCardNumber by remember { mutableStateOf("") }
    
    // Or save obfuscated version
    var lastFourDigits by rememberSaveable { mutableStateOf("") }
}
```

---