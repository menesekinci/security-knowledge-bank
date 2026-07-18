---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "3. Navigation Security"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 4/8
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