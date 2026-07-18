---
source: "languages/kotlin/android-security-deep.md"
title: "Android Security Deep Dive"
heading: "1. Intent Interception"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [content, intent, interception, javascript, kotlin, language-vuln, overview, provider, table, webview]
chunk: 4/9
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