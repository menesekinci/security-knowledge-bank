---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "1. Side Effects Security"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 2/8
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