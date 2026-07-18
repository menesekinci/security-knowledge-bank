---
source: "languages/kotlin/case-studies/android-case-studies.md"
title: "Android / Kotlin Case Studies"
heading: "Case Study 3: Android Content Provider SQL Injection (Bug Bounty Writeup)"
category: "case-study"
language: "kotlin"
severity: "high"
tags: [case, case-study, kotlin, references, study]
chunk: 4/6
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