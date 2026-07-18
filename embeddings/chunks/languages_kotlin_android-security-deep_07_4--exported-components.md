---
source: "languages/kotlin/android-security-deep.md"
title: "Android Security Deep Dive"
heading: "4. Exported Components"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [content, intent, interception, javascript, kotlin, language-vuln, overview, provider, table, webview]
chunk: 7/9
---

## 4. Exported Components

Android components (Activities, Services, BroadcastReceivers, ContentProviders) are "exported" if they have intent filters or `android:exported="true"`. This allows other apps to launch them.

### Vulnerable Exported Components

```xml
<!-- VULNERABLE: Exported activity with no permission check -->
<activity
    android:name=".AdminPanelActivity"
    android:exported="true">
    <!-- Any app can launch this admin panel! -->
</activity>

<!-- VULNERABLE: Exported broadcast receiver -->
<receiver
    android:name=".SecretBroadcastReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.example.SECRET_ACTION" />
    </intent-filter>
</receiver>

<!-- VULNERABLE: Exported service -->
<service
    android:name=".DataUploadService"
    android:exported="true" />
```

### Secure Component Declaration

```xml
<!-- SECURE: Only export what's necessary -->
<!-- Internal-only activity -->
<activity
    android:name=".AdminPanelActivity"
    android:exported="false" />

<!-- Authenticated external access with permission -->
<activity
    android:name=".ShareActivity"
    android:exported="true"
    android:permission="com.example.SHARE_PERMISSION">
    <intent-filter>
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="text/plain" />
    </intent-filter>
</activity>

<!-- Broadcast receiver with custom permission -->
<receiver
    android:name=".AuthenticatedReceiver"
    android:exported="true"
    android:permission="com.example.BROADCAST_PERMISSION" />

<!-- Service NOT exported -->
<service
    android:name=".BackgroundSyncService"
    android:exported="false" />
```

### Kotlin Runtime Exported Check

```kotlin
// SECURE: Runtime validation for exported components
class ProtectedActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Verify caller is authorized
        val callingPackage = callingPackage
        if (!isCallerAuthorized(callingPackage)) {
            Log.w("ProtectedActivity", "Unauthorized caller: $callingPackage")
            finish()
            return
        }
        
        setContentView(R.layout.activity_protected)
    }
    
    private fun isCallerAuthorized(packageName: String?): Boolean {
        if (packageName == null) return false  // Called from within app
        
        // Check signature match (same developer)
        return packageManager.checkSignatures(
            packageName, packageName
        ) == PackageManager.SIGNATURE_MATCH
    }
}
```

---