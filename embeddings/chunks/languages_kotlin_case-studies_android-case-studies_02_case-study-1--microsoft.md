---
source: "languages/kotlin/case-studies/android-case-studies.md"
title: "Android / Kotlin Case Studies"
heading: "Case Study 1: Microsoft 'Dirty Stream' Attack — Android Content Provider Path Traversal"
category: "case-study"
language: "kotlin"
severity: "high"
tags: [case, case-study, kotlin, references, study]
chunk: 2/6
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