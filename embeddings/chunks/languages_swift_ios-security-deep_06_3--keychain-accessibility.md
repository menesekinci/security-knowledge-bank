---
source: "languages/swift/ios-security-deep.md"
title: "iOS Security Deep Dive"
heading: "3. Keychain Accessibility"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [accessibility, data, keychain, language-vuln, overview, protection, swift, table, transport]
chunk: 6/9
---

## 3. Keychain Accessibility

The iOS Keychain provides encrypted storage for small secrets. The `kSecAttrAccessible` attribute controls when the item is accessible.

### Keychain Accessibility Levels

| kSecAttrAccessible value | Security | Use case |
|---|---|---|
| `kSecAttrAccessibleAlways` | 🚫 Lowest | Never use — accessible even when locked |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | 🚫 Low | Never use — accessible when locked, not backed up |
| `kSecAttrAccessibleWhenUnlocked` | ✅ Good | Default — accessible when device unlocked |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | ✅ Better | Same + not backed up to iCloud |
| `kSecAttrAccessibleAfterFirstUnlock` | ⚠️ Use carefully | Accessible after first boot unlock |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | ⚠️ | Same + not backed up |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | 🔒 Best | Requires device passcode |

### Vulnerable Keychain Usage

```swift
// VULNERABLE: Using "Always" accessibility — accessible when locked!
import Security

class InsecureKeychain {
    func savePassword(_ password: String, for account: String) {
        let data = password.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // VULNERABLE: Accessible even when device is locked!
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        ]
        
        SecItemAdd(query as CFDictionary, nil)
    }
}
```

### Secure Keychain Usage

```swift
// SECURE: Proper keychain accessibility
import Foundation
import Security
import LocalAuthentication

class SecureKeychainManager {
    
    /// Save data with biometric protection (requires FaceID/TouchID + passcode)
    @available(iOS 11.3, *)
    func saveWithBiometrics(_ data: Data, for key: String) throws {
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            nil
        )
        
        guard let accessControl = accessControl else {
            throw KeychainError.accessControlFailed
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
            kSecUseAuthenticationContext as String: LAContext(),
        ]
        
        var status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Update existing item
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key,
            ]
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessControl as String: accessControl,
            ]
            status = SecItemUpdate(updateQuery as CFDictionary, attributes as CFDictionary)
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
    
    /// Save without biometrics, but with device-only scope
    func saveDeviceOnly(_ data: Data, for key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false, // Don't sync to iCloud
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
}
```

---