---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "5. Implicit Intent Handling in Compose"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 6/8
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