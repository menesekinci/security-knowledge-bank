---
source: "languages/kotlin/android-security-deep.md"
title: "Android Security Deep Dive"
heading: "2. Content Provider Leaks"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [content, intent, interception, javascript, kotlin, language-vuln, overview, provider, table, webview]
chunk: 5/9
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