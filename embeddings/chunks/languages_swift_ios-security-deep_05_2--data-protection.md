---
source: "languages/swift/ios-security-deep.md"
title: "iOS Security Deep Dive"
heading: "2. Data Protection"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [accessibility, data, keychain, language-vuln, overview, protection, swift, table, transport]
chunk: 5/9
---

## 2. Data Protection

iOS Data Protection encrypts files using class-based encryption tied to device lock state.

### File Protection Classes

| Class | Description | When accessible |
|---|---|---|
| `Complete` | Encrypted until device unlocked | After first unlock |
| `CompleteUnlessOpen` | File openable while locked, new writes encrypted | Mixed |
| `CompleteUntilFirstUserAuthentication` | Encrypted until first unlock after boot | After first unlock |
| `NoProtection` | No encryption (⚠️) | Always |

### Vulnerable File Protection

```swift
// VULNERABLE: No data protection on sensitive file
import Foundation

class InsecureDataStorage {
    func saveToken(_ token: String) {
        let filePath = getDocumentsDirectory().appendingPathComponent("auth_token.dat")
        
        // No protection attributes — file is accessible even when device is locked!
        try? token.write(to: filePath, atomically: true, encoding: .utf8)
    }
    
    // Also vulnerable: UserDefaults for sensitive data
    func saveToUserDefaults(_ token: String) {
        UserDefaults.standard.set(token, forKey: "auth_token")
        // UserDefaults is NOT encrypted!
    }
}
```

### Secure File Protection

```swift
// SECURE: Data protection on sensitive files
import Foundation

class SecureDataStorage {
    func saveSensitiveData(_ data: Data, filename: String) throws {
        let filePath = getDocumentsDirectory().appendingPathComponent(filename)
        
        // Write with complete protection
        try data.write(to: filePath, options: .completeFileProtection)
    }
    
    func saveTokenToKeychain(_ token: String, service: String, account: String) throws {
        // Use Keychain instead of files for tokens
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
}

// File protection for Core Data
let container = NSPersistentContainer(name: "AppData")
container.loadPersistentStores { description, error in
    // Core Data automatically uses NSFileProtectionComplete
    // But verify:
    let storeURL = description.url!
    let resourceValues = try? (storeURL as NSURL).resourceValues(forKeys: [
        URLResourceKey.fileProtectionKey
    ])
    assert(resourceValues?[URLResourceKey.fileProtectionKey] as? String == 
           URLFileProtection.complete.rawValue)
}
```

---