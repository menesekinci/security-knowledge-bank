---
source: "languages/kotlin/case-studies/android-case-studies.md"
title: "Android / Kotlin Case Studies"
heading: "Case Study 2: Microsoft Android SDK Intent Redirection (2025-2026)"
category: "case-study"
language: "kotlin"
severity: "high"
tags: [case, case-study, kotlin, references, study]
chunk: 3/6
---

## Case Study 2: Microsoft Android SDK Intent Redirection (2025-2026)

### Incident Overview
- **Date**: Published April 2026 (vulnerability existed before)
- **Researchers**: Microsoft Security Response Center
- **Severity**: Critical (affecting millions of apps via third-party SDK)
- **Impact**: Over 1 billion app installs vulnerable

### Description
Microsoft discovered a severe **intent-redirection vulnerability** in a widely deployed third-party Android SDK. The SDK's exported component accepted arbitrary intents and forwarded them to internal app components without validation, allowing malicious apps to access protected features and sensitive user data.

### Technical Details
The vulnerable SDK exported an Activity with an intent filter:
```xml
<!-- Vulnerable SDK component -->
<activity
    android:name="com.vulnerable.sdk.BridgeActivity"
    android:exported="true"
    android:taskAffinity="">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

Inside the activity:
```kotlin
// VULNERABLE: Forwards received intent without validation
class BridgeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Takes the "target" intent from the incoming intent
        val targetIntent = intent.getParcelableExtra<Intent>("target")
        if (targetIntent != null) {
            // VULNERABLE: No validation! Attacker can target any component
            startActivity(targetIntent)
            
            // Even worse — attacker can access:
            // 1. Internal activities (exported=false bypassed)
            // 2. Content providers (read credentials)
            // 3. Services (trigger background operations)
        }
    }
}
```

### Attack Chain
1. Malicious app sends intent to the vulnerable SDK's bridge Activity
2. The `target` extra contains an intent targeting a protected internal component
3. The SDK forwards the intent, bypassing `android:exported=false` on the target
4. Malicious app can launch admin panels, steal data, or trigger privileged operations

### Impact
- Over 1 billion app installs across the Google Play Store
- Data theft from internal app storage (databases, shared preferences)
- Privilege escalation to access protected app features
- Silent operations: send SMS, make calls, access camera/microphone

### Mitigation Steps for SDK Developers
```kotlin
// SECURE: Validate intent sources and targets
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    
    val targetIntent = intent.getParcelableExtra<Intent>("target")
        ?: return
    
    // 1. Verify caller identity
    val callingPackage = callingPackage
    if (callingPackage == null || !isTrustedCaller(callingPackage)) {
        finish()
        return
    }
    
    // 2. Validate target component
    val targetComponent = targetIntent.component
    if (targetComponent == null || 
        targetComponent.packageName != packageName ||
        targetComponent.className in blacklistedComponents) {
        finish()
        return
    }
    
    // 3. Strip dangerous extras
    targetIntent.replaceExtras(Bundle())
    
    startActivity(targetIntent)
}
```

### Lessons for Android Developers
1. **Validate all forwarded intents** — both the source and target
2. Never forward intents from `getParcelableExtra<Intent>(...)` without validation
3. Use `callingPackage` to verify who sent the intent
4. Maintain an allowlist of valid target components
5. Strip all extras from forwarded intents

### Sources
- https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/
- https://developer.android.com/privacy-and-security/risks/intent-redirection
- https://support.google.com/faqs/answer/9267555

---