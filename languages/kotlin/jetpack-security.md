# 🎯 Jetpack Compose Security Guide

> **Category:** Languages / Kotlin / Jetpack Compose
> **Last Updated:** July 2026
> **Description:** Jetpack Compose-specific security — side effects security, `remember` misuse, navigation security, deep link bypasses, and common vulnerability patterns in Compose-based Android apps.

---

## 1. Side Effects Security

### The Side Effect Danger Zone

Compose's declarative model means side effects run at any recomposition — making them a prime vector for injection and logic flaws:

```
┌──────────────────────────────────────────────────────────┐
│           COMPOSE SIDE EFFECTS — RISK MATRIX              │
├────────────────┬──────────┬──────────────────────────────┤
│  Effect API    │ Risk     │ Danger                       │
├────────────────┼──────────┼──────────────────────────────┤
│  LaunchedEffect │ Medium  │ Uncontrolled network calls   │
│  rememberCoroutineScope │ Medium │ Task leaks         │
│  SideEffect    │ High     │ Runs on EVERY recomposition  │
│  DisposableEffect │ Low  │ Cleanup, generally safe      │
│  derivedStateOf │ Low     │ Computation only            │
│  snapshotFlow   │ Medium  │ Stream processing            │
│  produceState   │ Medium  │ Producer cancellation        │
└────────────────┴──────────┴──────────────────────────────┘
```

### LaunchedEffect — Network Call Injection

```kotlin
// VULNERABLE: LaunchedEffect with user-controlled key triggers network calls
@Composable
fun UserProfile(userId: String) {
    var profile by remember { mutableStateOf<Profile?>(null) }
    
    // ⚠️ userId is user-controlled — attacker can trigger ANY ID lookup
    LaunchedEffect(userId) {
        profile = api.fetchProfile(userId)  // No authorization check!
    }
    
    // ...
}

// SECURE: Authorize access before fetching
@Composable
fun UserProfile(userId: String, authService: AuthService) {
    var profile by remember { mutableStateOf<Profile?>(null) }
    
    LaunchedEffect(userId) {
        if (authService.canViewProfile(userId)) {
            profile = api.fetchProfile(userId)
        } else {
            // Log unauthorized access attempt
            analytics.logUnauthorizedAccess(userId, authService.currentUserId())
        }
    }
    
    if (profile == null) {
        Text("Access denied")
    } else {
        ProfileContent(profile!!)
    }
}
```

### SideEffect — Unitended Data Leakage

```kotlin
// VULNERABLE: SideEffect runs on EVERY recomposition
@Composable
fun SensitiveDataView(data: String) {
    // Runs on every recomposition — could leak data to analytics
    SideEffect {
        // ⚠️ Even if data hasn't changed, this runs!
        analytics.track("data_viewed", mapOf("data_hash" to data.hashCode()))
    }
    
    Text(data)
}

// SECURE: Use LaunchedEffect with stable key
@Composable
fun SensitiveDataView(data: String) {
    LaunchedEffect(data) {
        // Runs only when `data` changes
        analytics.track("data_viewed", mapOf("data_hash" to data.hashCode()))
    }
    
    Text(data)
}
```

### DisposableEffect — Secure Cleanup

```kotlin
// VULNERABLE: No cleanup of sensitive resources
@Composable
fun BiometricAuthView(onResult: (Boolean) -> Unit) {
    // ⚠️ Auth session not cleaned up when composable leaves composition
    DisposableEffect(Unit) {
        val authManager = BiometricAuthManager()
        authManager.startListening { success ->
            onResult(success)
        }
        // NO onDispose! — resource leak!
    }
}

// SECURE: Always clean up auth sessions
@Composable
fun BiometricAuthView(onResult: (Boolean) -> Unit) {
    DisposableEffect(Unit) {
        val authManager = BiometricAuthManager()
        authManager.startListening { success ->
            onResult(success)
        }
        
        onDispose {
            authManager.stopListening()  // Clean up
        }
    }
}
```

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

## 3. Navigation Security

### Jetpack Navigation Deep Link Bypass

In 2024, a critical vulnerability was discovered in the Jetpack Navigation library that allowed bypassing authentication screens via deep links. The library's implicit deep link handling allowed **any app on the device** to open any screen in the navigation graph — bypassing `android:exported="false"` on activities.

**Reference**: [Android Jetpack Navigation: Go Even Deeper — PT SWARM](https://swarm.ptsecurity.com/android-jetpack-navigation-go-even-deeper/)

```kotlin
// VULNERABLE: Navigation graph with implicit deep links
@Composable
fun AppNavGraph(navController: NavHostController) {
    NavHost(navController = navController, startDestination = "login") {
        composable("login") { LoginScreen(navController) }
        
        composable(
            "profile/{userId}",
            deepLinks = listOf(
                navDeepLink { uriPattern = "https://myapp.com/profile/{userId}" }
            )
        ) { backStackEntry ->
            // ⚠️ Directly navigates to profile — no auth check!
            ProfileScreen(userId = backStackEntry.arguments?.getString("userId"))
        }
        
        composable(
            "admin/settings",
            deepLinks = listOf(
                navDeepLink { uriPattern = "myapp://admin/settings" }
            )
        ) { 
            // ⚠️ Implicit deep link bypasses activity export restrictions!
            AdminSettingsScreen()
        }
    }
}
```

**The Attack:**
```bash
# Any app on the device can trigger this:
adb shell am start -d "myapp://admin/settings" -p com.victim.app
# → Opens AdminSettingsScreen without authentication!
```

### Secure Navigation Pattern

```kotlin
// SECURE: Validate deep links with authentication
@Composable
fun SecureNavGraph(navController: NavHostController, authService: AuthService) {
    NavHost(navController = navController, startDestination = "login") {
        composable("login") { LoginScreen(navController) }
        
        composable(
            "profile/{userId}",
            deepLinks = listOf(
                navDeepLink { uriPattern = "https://myapp.com/profile/{userId}" }
            )
        ) { backStackEntry ->
            val userId = backStackEntry.arguments?.getString("userId")
            
            // ⚠️ IMPORTANT: Check authentication for ALL deep links
            if (!authService.isAuthenticated) {
                navController.navigate("login") {
                    popUpTo("login") { inclusive = true }
                }
                return@composable
            }
            
            // Validate authorization for the specific resource
            if (userId != null && authService.canViewProfile(userId)) {
                ProfileScreen(userId = userId)
            } else {
                AccessDeniedScreen()
            }
        }
    }
}
```

### Navigation Argument Injection

```kotlin
// VULNERABLE: Unvalidated navigation arguments
composable(
    route = "profile/{userId}",
    arguments = listOf(
        navArgument("userId") { 
            type = NavType.StringType
            // ⚠️ No defaultValue or validation!
        }
    )
) { backStackEntry ->
    val userId = backStackEntry.arguments?.getString("userId") ?: ""
    
    // If userId is empty or malicious, this could crash or leak data
    UserProfileScreen(userId = userId)
}

// SECURE: Validate arguments
composable(
    route = "profile/{userId}",
    arguments = listOf(
        navArgument("userId") { 
            type = NavType.StringType
            defaultValue = ""
            nullable = false
        }
    )
) { backStackEntry ->
    val userId = backStackEntry.arguments?.getString("userId") ?: ""
    
    // Validate the input
    if (userId.isBlank() || !isValidUUID(userId)) {
        ErrorScreen("Invalid user ID")
        return@composable
    }
    
    UserProfileScreen(userId = userId)
}
```

### Navigation with Deep Link Workaround (Navigation 2.8.1 fix)

```kotlin
// Google fixed the Jetpack Navigation deep link bypass in v2.8.1 (Sep 2024)
// But apps on older versions need a workaround:

// Workaround: Use a navigation interceptor
@Composable
fun SecureNavHost(
    navController: NavHostController,
    authService: AuthService
) {
    // Track navigation events
    DisposableEffect(navController) {
        val listener = NavController.OnDestinationChangedListener { _, dest, args ->
            val deepLink = dest.getDeepLink()
            if (deepLink != null && !authService.isAuthenticated) {
                // Block deep link navigation if not authenticated
                navController.navigate("login") {
                    popUpTo(0) { inclusive = true }
                }
            }
        }
        navController.addOnDestinationChangedListener(listener)
        
        onDispose {
            navController.removeOnDestinationChangedListener(listener)
        }
    }
    
    NavHost(navController = navController, startDestination = "home") {
        // ... composables
    }
}
```

**References**:
- [Android Jetpack Navigation: Go Even Deeper — PT SWARM](https://swarm.ptsecurity.com/android-jetpack-navigation-go-even-deeper/)
- [Workaround for Jetpack Navigation Vulnerability](https://medium.com/@gregkorossy/workaround-for-jetpack-navigation-vulnerability-1ffce1730913)
- [Unsafe use of deep links — Android Security](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks)

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

## 5. Implicit Intent Handling in Compose

```kotlin
// VULNERABLE: Handling implicit intents without validation
@Composable
fun DeepLinkHandler(navController: NavHostController) {
    val context = LocalContext.current
    
    LaunchedEffect(Unit) {
        // ⚠️ Handles ANY intent without validation
        val intent = (context as Activity).intent
        if (intent.action == Intent.ACTION_VIEW && intent.data != null) {
            navigateToDeepLink(navController, intent.data!!)
        }
    }
}

// SECURE: Validate source and data
@Composable
fun SecureDeepLinkHandler(navController: NavHostController) {
    val context = LocalContext.current
    val authService = LocalAuthChecker.current
    
    LaunchedEffect(Unit) {
        val activity = context as Activity
        val intent = activity.intent
        
        if (intent?.action == Intent.ACTION_VIEW && intent.data != null) {
            val uri = intent.data!!
            
            // 1. Verify the calling package (if any)
            val callingPackage = activity.callingPackage
            if (callingPackage != null) {
                // Called from another app — be extra strict
                if (!isTrustedCaller(callingPackage)) {
                    return@LaunchedEffect
                }
            }
            
            // 2. Verify authentication
            if (!authService.isAuthenticated) {
                navController.navigate("login")
                return@LaunchedEffect
            }
            
            // 3. Validate and sanitize the URI
            if (!isValidDeepLink(uri)) {
                return@LaunchedEffect
            }
            
            navigateToDeepLink(navController, uri)
        }
    }
}
```

---

## 6. Secure Compose Hardening Checklist

- [ ] `LaunchedEffect` key does not include user-controlled data that enables IDOR
- [ ] `SideEffect` is NOT used for security-critical operations (use `LaunchedEffect`)
- [ ] `DisposableEffect` always has `onDispose` for cleanup of auth/biometric sessions
- [ ] `rememberSaveable` does NOT store sensitive data (tokens, passwords, PII)
- [ ] `remember` cleared of sensitive data after use
- [ ] Navigation deep links validate authentication BEFORE navigation
- [ ] `navArgument` has proper type validation and defaultValue
- [ ] `CompositionLocal` exposes minimal read-only interfaces, not full services
- [ ] `CompositionLocal` scope is as narrow as possible
- [ ] Implicit intents validate calling package and URI scheme
- [ ] `@android:exported="false"` is not relied upon for Compose navigation security
- [ ] Deep link workaround applied for Navigation < 2.8.1

---

## References

- [Android Jetpack Navigation: Go Even Deeper — PT SWARM](https://swarm.ptsecurity.com/android-jetpack-navigation-go-even-deeper/)
- [Unsafe use of deep links — Android Developer Security](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks)
- [Jetpack Navigation Deep Link Bypass Workaround](https://medium.com/@gregkorossy/workaround-for-jetpack-navigation-vulnerability-1ffce1730913)
- [Android Security Bulletin — December 2025](https://source.android.com/docs/security/bulletin/2025-12-01)
- [OWASP Android Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Jetpack Compose Side Effects Documentation](https://developer.android.com/jetpack/compose/side-effects)
- [Android Developer — Security Risks](https://developer.android.com/privacy-and-security/risks)
