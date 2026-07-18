# Jetpack Navigation Deep Link Bypass — PT SWARM Discovery

**Language:** Kotlin / Android
**Vulnerability Type:** Deep Link Authentication Bypass
**Date:** August 2024 (disclosed)
**Fixed In:** Navigation Library v2.8.1 (September 2024)
**Researchers:** PT SWARM Security Team

## Overview

Security researchers at PT SWARM discovered a critical vulnerability in Android's **Jetpack Navigation** library (both Fragment and Compose variants) that allowed **any app on the device to open any screen** in a target application — bypassing `android:exported="false"` on Activities and any authentication requirements. The vulnerability was in the implicit deep link processing mechanism of the Navigation library.

## Root Cause

The Jetpack Navigation library processes implicit deep links through a system that didn't properly validate the navigation destination against authentication requirements. When a navigation graph registered deep links via `navDeepLink { uriPattern = ... }`, any application on the device could send an intent matching that pattern and bypass:

1. **Activity export restrictions** (`android:exported="false"`)
2. **Authentication checks** (if the deep link handled navigation before auth)
3. **Navigation flow restrictions** (skipping required intermediate screens)

## Technical Details

### Vulnerable Navigation Setup
```kotlin
// VULNERABLE: Navigation graph with implicit deep links
@Composable
fun AppNavGraph(navController: NavHostController) {
    NavHost(navController = navController, startDestination = "login") {
        composable(
            "login",
            // Login screen with auth check
        ) { LoginScreen(navController) }
        
        composable(
            "profile/{userId}",
            deepLinks = listOf(
                navDeepLink { uriPattern = "https://myapp.com/profile/{userId}" }
            )
        ) { backStackEntry ->
            // ⚠️ Attacker sends intent → directly opens profile screen!
            // No auth check before displaying sensitive user data
            val userId = backStackEntry.arguments?.getString("userId")
            ProfileScreen(userId = userId)  // No authorization!
        }
        
        composable(
            "admin/settings",
            deepLinks = listOf(
                navDeepLink { uriPattern = "myapp://admin/settings" }
            )
        ) { AdminSettingsScreen() }
    }
}
```

### The Attack
```bash
# From any app on the device, send an intent:
adb shell am start -W -a android.intent.action.VIEW \
    -d "https://myapp.com/profile/attacker-chosen-id" \
    com.target.app

# OR for custom scheme:
adb shell am start -W -a android.intent.action.VIEW \
    -d "myapp://admin/settings" \
    com.target.app

# Result: Opens the profile/settings screen WITHOUT authentication!
```

## Impact

- **Authentication Bypass**: Any app on the device could open any deep-linked screen
- **Data Access**: Profile information, settings, and potentially admin functions exposed
- **Zero-Click Exploit**: No user interaction needed (for implicit deep links)
- **No Permissions Required**: The attacking app needs no Android permissions
- **All Navigation versions before 2.8.1 were affected**

## Fix / Workaround

### Official Fix (Navigation 2.8.1+)
Google fixed the issue in Navigation library v2.8.1 by properly validating implicit deep link sources.

### Workaround for Older Versions
```kotlin
@Composable
fun SecureNavHost(
    navController: NavHostController,
    authService: AuthService
) {
    // Interceptor to block deep link navigation when not authenticated
    DisposableEffect(navController) {
        val listener = NavController.OnDestinationChangedListener { _, dest, args ->
            val deepLink = dest.getDeepLink()
            
            // If we're navigating to a destination via deep link
            // and user is not authenticated, redirect to login
            if (deepLink != null && !authService.isAuthenticated) {
                // Use handler to navigate after current navigation completes
                navController.currentBackStackEntry?.savedStateHandle?.set(
                    "deep_link_redirect", true
                )
                
                handler.post {
                    navController.navigate("login") {
                        popUpTo(0) { inclusive = true }
                    }
                }
            }
        }
        
        navController.addOnDestinationChangedListener(listener)
        
        onDispose {
            navController.removeOnDestinationChangedListener(listener)
        }
    }
    
    NavHost(navController = navController, startDestination = "login") {
        // All composables...
    }
}
```

## Secure Navigation Pattern

```kotlin
// SECURE: Always check auth in deep link destinations
composable(
    "profile/{userId}",
    deepLinks = listOf(
        navDeepLink { uriPattern = "https://myapp.com/profile/{userId}" }
    )
) { backStackEntry ->
    val userId = backStackEntry.arguments?.getString("userId")
    
    // CRITICAL: Check authentication AND authorization
    if (!authService.isAuthenticated) {
        navController.navigate("login") {
            popUpTo("login") { inclusive = true }
        }
        return@composable
    }
    
    if (userId != null && !authService.canViewProfile(userId)) {
        ErrorScreen("Access denied")
        return@composable
    }
    
    ProfileScreen(userId = userId)
}
```

## Lessons

1. **Deep links bypass normal navigation flow** — always re-authenticate in deep link destinations
2. **`android:exported="false"` is NOT sufficient** for Navigation library screens
3. **Every deep link destination must independently verify authentication and authorization**
4. **Navigation library version matters** — update to ≥ 2.8.1
5. **Implicit deep links can be sent by ANY app** — never trust the source

## References

- [PT SWARM — Android Jetpack Navigation: Go Even Deeper](https://swarm.ptsecurity.com/android-jetpack-navigation-go-even-deeper/)
- [Workaround for Jetpack Navigation Vulnerability](https://medium.com/@gregkorossy/workaround-for-jetpack-navigation-vulnerability-1ffce1730913)
- [Android Developer — Unsafe Use of Deep Links](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks)
- [Previous PT SWARM Research — Jetpack Navigation Deep Links](https://swarm.ptsecurity.com/android-jetpack-navigation-deep-links-handling-exploitation/)
