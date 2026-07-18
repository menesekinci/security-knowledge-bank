# Android / Kotlin Case Studies

> **Category:** Languages / Kotlin / Case Studies
> **Last Updated:** July 2026
> **Description:** Real-world security incidents, bug bounty writeups, and breach post-mortems affecting Android/Kotlin applications from 2024-2025.

---

## Case Study 1: Microsoft "Dirty Stream" Attack — Android Content Provider Path Traversal

### Incident Overview
- **Date**: May 2024
- **Researchers**: Microsoft 365 Defender Research Team
- **Advisory**: Dirty Stream Attack
- **Severity**: High (affecting billions of Android devices)
- **CVEs**: Multiple (assigned per affected app)

### Description
Microsoft discovered a widespread vulnerability pattern in Android applications where **content providers improperly handled file paths**, allowing malicious apps to read or overwrite files in another app's internal storage. This "Dirty Stream" attack abuses Android's content provider URI handling combined with path traversal.

### Technical Details
The vulnerability works because:
1. A vulnerable app exposes a content provider with `grantUriPermissions`
2. The provider doesn't validate the `_display_name` or path segments in content URIs
3. A malicious app crafts a content URI with path traversal (e.g., `../../../data/data/com.victim/databases/credentials.db`)
4. The provider blindly returns a file descriptor for the traversal path

### Vulnerable Code Pattern
```java
// VULNERABLE: Content provider that trusts URI paths
public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    // DIRECTLY uses URI path — vulnerable to traversal!
    File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

### Secure Code Pattern
```kotlin
// SECURE: Validate file paths against the allowed directory
class SecureProvider : ContentProvider() {
    private val baseDir = File(context.filesDir, "shared")
    
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val fileName = uri.lastPathSegment ?: return null
        
        // Validate: no path traversal, no special characters
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\0")) {
            throw SecurityException("Invalid filename: $fileName")
        }
        
        val file = File(baseDir, fileName).normalize()
        
        // Double-check the resolved path is within the allowed directory
        if (!file.canonicalPath.startsWith(baseDir.canonicalPath)) {
            throw SecurityException("Path traversal detected")
        }
        
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }
}
```

### Impact
- **Billions** of Android devices vulnerable (hundreds of popular apps affected)
- Attackers could overwrite app code/config, leading to arbitrary code execution
- Data theft from app-internal databases and shared preferences
- Apps with `requestLegacyExternalStorage` were particularly exposed

### Affected Apps
Included Xiaomi File Manager (CVE-2024-0044), WPS Office, and many others with custom content providers

### Lessons for Android Developers
1. **Always validate and sanitize** file paths from content URIs
2. Use `File.getCanonicalPath()` and compare against `baseDir.canonicalPath`
3. Do NOT use `Uri.getLastPathSegment()` directly to construct file paths
4. Limit `grantUriPermissions` to only specific, necessary URIs

### Sources
- https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/
- https://www.darkreading.com/cloud-security/billions-android-devices-open-dirty-stream-attack
- https://developer.android.com/privacy-and-security/risks/dirty-stream

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

## Case Study 3: Android Content Provider SQL Injection (Bug Bounty Writeup)

### Incident Overview
- **Date**: 2024
- **Platform**: Android
- **Severity**: High (data leak of all user records)
- **Bounty**: $2,000+

### Description
A bug bounty researcher discovered that a popular Android app's **exported Content Provider was vulnerable to SQL injection**. The provider used raw string concatenation instead of parameterized queries in its `query()` method, allowing any app on the device to extract all user data from the provider's database.

### Technical Details

#### Vulnerable Code
```kotlin
// VULNERABLE: Content provider with SQL injection
class DataProvider : ContentProvider() {
    override fun query(uri: Uri, projection: Array<String>?,
                       selection: String?, selectionArgs: Array<String>?,
                       sortOrder: String?): Cursor {
        
        // VULNERABLE: Appends URI path directly to SQL query
        val userId = uri.lastPathSegment  // "1 UNION SELECT * FROM credit_cards"
        
        val db = dbHelper.readableDatabase
        return db.rawQuery("SELECT * FROM users WHERE id = $userId", null)
    }
}
```

#### Exploitation
```bash
# Using Android Debug Bridge (ADB) or another malicious app:
content query --uri content://com.victim.provider/users/1%20UNION%20SELECT%20*%20FROM%20credit_cards

# The provider executes:
# SELECT * FROM users WHERE id = 1 UNION SELECT * FROM credit_cards
# And returns all credit card data!
```

### Impact
- Complete data exfiltration from app's database
- All user records, including financial data and PII, accessible to any installed app
- No permissions required beyond `INTERNET` (for exfiltration)

### Secure Code
```kotlin
// SECURE: Use parameterized queries with a UriMatcher
class SecureProvider : ContentProvider() {
    
    companion object {
        private val URI_MATCHER = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI("com.victim.provider", "users", USERS)
            addURI("com.victim.provider", "users/#", USER_BY_ID)
        }
    }
    
    override fun query(uri: Uri, projection: Array<String>?,
                       selection: String?, selectionArgs: Array<String>?,
                       sortOrder: String?): Cursor {
        
        val db = dbHelper.readableDatabase
        
        return when (URI_MATCHER.match(uri)) {
            USER_BY_ID -> {
                // Safe extraction of numeric ID
                val userId = uri.lastPathSegment?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid user ID")
                
                // Parameterized query — safe from SQL injection
                db.query("users", projection, "id = ?",
                         arrayOf(userId.toString()), null, null, sortOrder)
            }
            else -> throw IllegalArgumentException("Unknown URI")
        }
    }
}
```

### Lessons for Android Developers
1. **Never use `rawQuery()` with string concatenation** — always use parameterized queries
2. Use `UriMatcher` to safely parse and validate URIs
3. Cast URI path segments to expected types (e.g., `.toIntOrNull()`)
4. Do NOT expose Content Providers unnecessarily (`android:exported="false"`)
5. Require a custom permission for any exported provider

### Sources
- https://cyberweapons.medium.com/critical-android-bug-insecure-exported-components-content-leak-a-real-world-writeup-dada800f7ee6
- https://redfoxsecurity.medium.com/exploiting-content-providers-in-android-applications-a75cbda2a5c7
- https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html

---

## Case Study 4: Parler Data Breach — Android Content Provider Metadata Leak

### Incident Overview
- **Date**: January 2024 (re-audit of 2021 breach)
- **Platform**: Android
- **Severity**: High (location data, private posts, user metadata)

### Description
The Parler social media app suffered a massive data breach in 2021, but a 2024 re-audit revealed that the Android app's exported **Content Provider** leaked geolocation metadata from every user post, even when location sharing was "disabled" in the UI. The provider exposed EXIF-like data embedded in media uploads, including GPS coordinates, device model, and timestamps.

### Technical Analysis
The Android Parler app had an exported content provider (`android:exported="true"`) that exposed internal media metadata, including GPS coordinates from EXIF data, device identifiers, and server-side timestamps. The provider had no permission check.

### Impact
- Public exposure of user GPS locations (home addresses, workplaces)
- Private posts' metadata leaked even for locked/private accounts
- Timelines of user activity reconstructable from timestamps

### Lessons for Android Developers
1. **Check ALL exported components** for unnecessary data exposure
2. Content Providers should **never** be exported without strict permission requirements
3. Strip EXIF/location metadata from media before storing or exposing via providers
4. Use "signature" protection level for custom permissions to limit access to your app only

### Sources
- https://salt.security/blog/unpacking-the-parler-data-breach
- https://cyberweapons.medium.com/critical-android-bug-insecure-exported-components-content-leak-a-real-world-writeup-dada800f7ee6

---

## References

- [Microsoft — Dirty Stream Attack](https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/)
- [Microsoft — Android SDK Intent Redirection](https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/)
- [Android Developer — Security Risks](https://developer.android.com/privacy-and-security/risks)
- [OWASP Android Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [HackTricks — Android Content Provider Exploitation](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/drozer-tutorial/exploiting-content-providers.html)
- [Snyk — Android Intent-Based Security Vulnerabilities](https://labs.snyk.io/resources/exploring-android-intent-based-security-vulnerabilities-google-play/)
